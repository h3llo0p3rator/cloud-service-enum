"""Orchestrates ``cse azure unauth storage``.

Mirrors the AWS S3 runner: optional crawl → regex extraction + direct
targets + bruteforce → per-account multi-surface probes → per-container
listing/ACL/metadata probes → blob sampling → one
:class:`EnumerationRun` rendered by the shared Rich helpers and piped
through the standard report writers.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from rich.panel import Panel

from cloud_service_enum.azure.unauth.storage import (
    DEFAULT_CONTAINER_WORDLIST,
    AccountHit,
    ContainerHit,
    ContainerProbeReport,
    StorageProbeReport,
    bruteforce_accounts,
    extract_accounts,
    extract_containers,
    extract_sas_tokens,
    load_default_suffix_wordlist,
    probe_account,
    probe_container,
    scan_public_blobs,
)
from cloud_service_enum.core.display import render_service, render_summary
from cloud_service_enum.core.models import EnumerationRun, Provider, ServiceResult
from cloud_service_enum.core.output import get_console
from cloud_service_enum.core.unauth.common import (
    SHARED_CRAWL_DEFAULTS,
    build_cse_scope,
    build_identity,
    crawl_errors,
    crawl_if_url,
    crawl_summary_row,
    drop_empty,
    render_preamble,
    scan_pages_for_secrets,
    scope_hosts,
)
from cloud_service_enum.core.unauth.crawler import DEFAULT_USER_AGENT, FetchedPage


@dataclass
class StorageUnauthScope:
    """Inputs for ``cse azure unauth storage``."""

    target_url: str | None = None
    accounts: tuple[str, ...] = ()
    # Accepts ``<account>/<container>`` or bare ``<container>`` (applied
    # against every supplied account).
    containers: tuple[str, ...] = ()
    bruteforce: bool = False
    bruteforce_prefixes: tuple[str, ...] = ()
    bruteforce_wordlist: Path | None = None
    bruteforce_container: bool = False
    container_wordlist: Path | None = None
    max_blobs: int = 100
    max_blob_size_kb: int = 500
    max_pages: int = SHARED_CRAWL_DEFAULTS["max_pages"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()


async def run_storage_unauth(scope: StorageUnauthScope) -> EnumerationRun:
    """Crawl (optional) + probe every discovered / supplied storage account."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope(
        Provider.AZURE, "unauth-storage", scope.max_concurrency, scope.timeout_s
    )
    identity_label = (
        urlparse(scope.target_url).netloc if scope.target_url else "(account list)"
    )

    pages, stats = await crawl_if_url(
        scope.target_url,
        max_pages=scope.max_pages,
        max_concurrency=scope.max_concurrency,
        timeout_s=scope.timeout_s,
        user_agent=scope.user_agent,
        extra_hosts=tuple(scope.extra_hosts),
    )
    crawl_account_hits = extract_accounts(pages) if pages else []
    crawl_container_hits = extract_containers(pages) if pages else []
    sas_findings = extract_sas_tokens(pages) if pages else []
    secret_findings = scan_pages_for_secrets(pages)

    bruteforce_candidates = _build_bruteforce_candidates(scope)
    account_targets = _merge_account_targets(
        crawl_account_hits, scope.accounts, bruteforce_candidates
    )
    supplied_containers = _parse_supplied_containers(scope.containers, account_targets)
    container_wordlist = _load_container_wordlist(scope)

    render_preamble(
        console,
        provider=Provider.AZURE,
        service_label="unauth-storage",
        cse_scope=cse_scope,
        identity_label=identity_label or "(unknown)",
        extras={
            "Target URL": scope.target_url or "(none)",
            "Accounts (direct)": ", ".join(scope.accounts) or "(none)",
            "Bruteforce accounts": f"{len(bruteforce_candidates)} candidates"
            if bruteforce_candidates
            else "off",
            "Built-in container list": f"{len(container_wordlist)} names",
            "Containers (direct)": len(supplied_containers) + len(crawl_container_hits),
            "Max blobs / container": scope.max_blobs,
            "Max blob size (KB)": scope.max_blob_size_kb,
            "In-scope hosts": ", ".join(scope_hosts(scope.target_url, scope.extra_hosts))
            or "(none)",
        },
    )

    svc_started = datetime.now(timezone.utc)
    account_reports: list[StorageProbeReport] = []
    container_reports: list[ContainerProbeReport] = []
    sampled_blobs: list[dict[str, Any]] = []
    blob_secrets: list[dict[str, Any]] = []
    errors = crawl_errors(scope.target_url, pages)

    if account_targets:
        sem = asyncio.Semaphore(scope.max_concurrency)
        async with httpx.AsyncClient(
            timeout=scope.timeout_s,
            headers={"User-Agent": scope.user_agent},
            follow_redirects=False,
        ) as client:
            account_reports = await asyncio.gather(
                *[_probe_account_with_sem(client, sem, hit.name) for hit in account_targets]
            )

            existing_accounts = {
                r.account for r in account_reports if r.existence == "exists"
            }
            container_tasks: list[tuple[str, str, str, asyncio.Task[ContainerProbeReport]]] = []

            for hit in crawl_container_hits:
                if hit.account not in existing_accounts:
                    continue
                container_tasks.append(
                    (
                        hit.account,
                        hit.container,
                        hit.first_seen_url,
                        asyncio.create_task(
                            _probe_container_with_sem(client, sem, hit.account, hit.container)
                        ),
                    )
                )
            for hit in supplied_containers:
                if hit.account not in existing_accounts:
                    continue
                container_tasks.append(
                    (
                        hit.account,
                        hit.container,
                        hit.first_seen_url,
                        asyncio.create_task(
                            _probe_container_with_sem(client, sem, hit.account, hit.container)
                        ),
                    )
                )
            for account in existing_accounts:
                for container in container_wordlist:
                    container_tasks.append(
                        (
                            account,
                            container,
                            "(wordlist)",
                            asyncio.create_task(
                                _probe_container_with_sem(client, sem, account, container)
                            ),
                        )
                    )

            first_seen_by_container: dict[tuple[str, str], str] = {}
            for account, container, source, task in container_tasks:
                try:
                    report = await task
                except Exception as exc:  # noqa: BLE001
                    errors.append(
                        f"container {account}/{container}: {exc.__class__.__name__}: {exc}"
                    )
                    continue
                first_seen_by_container.setdefault((account, container), source)
                container_reports.append(report)

                if report.public_list and report.blob_keys:
                    sampled, report_secrets = await scan_public_blobs(
                        client,
                        report.account,
                        report.container,
                        report.blob_keys,
                        max_blobs=scope.max_blobs,
                        max_blob_size_kb=scope.max_blob_size_kb,
                    )
                    sampled_blobs.extend(sampled)
                    blob_secrets.extend(report_secrets)

    resources = _build_resources(
        scope,
        account_targets,
        account_reports,
        container_reports,
        sampled_blobs,
        blob_secrets,
        pages,
        stats,
        secret_findings,
        sas_findings,
        bruteforce_candidates,
    )
    cis_fields = _summarise(
        scope,
        account_targets,
        account_reports,
        container_reports,
        sampled_blobs,
        blob_secrets,
        secret_findings,
        sas_findings,
        bruteforce_candidates,
    )

    service = _finalise_service(
        "unauth-storage", svc_started, resources, cis_fields, errors
    )
    identity = build_identity(Provider.AZURE, identity_label or "(unknown)")
    run = _finalise_run(started, cse_scope, identity, service)

    render_service(console, service)
    _render_verdict(
        console,
        scope,
        account_reports,
        container_reports,
        blob_secrets,
        secret_findings,
        sas_findings,
    )
    render_summary(console, run)
    return run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _probe_account_with_sem(
    client: httpx.AsyncClient, sem: asyncio.Semaphore, account: str
) -> StorageProbeReport:
    async with sem:
        return await probe_account(client, account)


async def _probe_container_with_sem(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    account: str,
    container: str,
) -> ContainerProbeReport:
    async with sem:
        return await probe_container(client, account, container)


def _build_bruteforce_candidates(scope: StorageUnauthScope) -> list[str]:
    if not scope.bruteforce:
        return []
    if scope.bruteforce_wordlist is not None:
        suffixes = [
            line.strip()
            for line in scope.bruteforce_wordlist.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    else:
        suffixes = load_default_suffix_wordlist()
    return list(bruteforce_accounts(scope.bruteforce_prefixes, suffixes))


def _merge_account_targets(
    crawl_hits: list[AccountHit],
    direct: tuple[str, ...],
    bruteforce_candidates: list[str],
) -> list[AccountHit]:
    seen: dict[str, AccountHit] = {}
    for hit in crawl_hits:
        seen.setdefault(hit.name, hit)
    for name in direct:
        cleaned = name.strip().lower()
        if cleaned and cleaned not in seen:
            seen[cleaned] = AccountHit(
                name=cleaned, surfaces=set(), first_seen_url="(--account)"
            )
    for name in bruteforce_candidates:
        cleaned = name.strip().lower()
        if cleaned and cleaned not in seen:
            seen[cleaned] = AccountHit(
                name=cleaned, surfaces=set(), first_seen_url="(bruteforce)"
            )
    return list(seen.values())


def _parse_supplied_containers(
    raw: tuple[str, ...], accounts: list[AccountHit]
) -> list[ContainerHit]:
    """Accept ``--container acct/container`` or a bare container name.

    A bare ``<container>`` is applied against every ``--account`` input.
    """
    known_accounts = {a.name for a in accounts}
    out: list[ContainerHit] = []
    seen: set[tuple[str, str]] = set()
    for entry in raw:
        cleaned = entry.strip()
        if not cleaned:
            continue
        if "/" in cleaned:
            account, _, container = cleaned.partition("/")
            account = account.strip().lower()
            container = container.strip().lower()
            if not account or not container:
                continue
            key = (account, container)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                ContainerHit(account=account, container=container, first_seen_url="(--container)")
            )
            continue
        # Bare container name — fan out across every supplied account.
        for acct in known_accounts:
            key = (acct, cleaned.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(
                ContainerHit(
                    account=acct, container=cleaned.lower(), first_seen_url="(--container)"
                )
            )
    return out


def _load_container_wordlist(scope: StorageUnauthScope) -> list[str]:
    if scope.bruteforce_container:
        if scope.container_wordlist is None:
            return list(DEFAULT_CONTAINER_WORDLIST)
        return [
            line.strip()
            for line in scope.container_wordlist.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    return list(DEFAULT_CONTAINER_WORDLIST)


def _build_resources(
    scope: StorageUnauthScope,
    account_targets: list[AccountHit],
    account_reports: list[StorageProbeReport],
    container_reports: list[ContainerProbeReport],
    sampled_blobs: list[dict[str, Any]],
    blob_secrets: list[dict[str, Any]],
    pages: list[FetchedPage],
    stats: Any,
    crawl_secrets: list[dict[str, Any]],
    sas_findings: list[dict[str, Any]],
    bruteforce_candidates: list[str],
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []

    # Only surface storage accounts we could confirm as existing.
    for report in account_reports:
        if report.existence != "exists":
            continue
        surfaces = ", ".join(report.surfaces_live)
        resources.append(
            drop_empty(
                {
                    "kind": "storage_account",
                    "id": report.account,
                    "name": report.account,
                    "surfaces": surfaces or "-",
                    "blob_list_public": _tri(report.blob_list_public),
                    "file_list_public": _tri(report.file_list_public),
                    "queue_list_public": _tri(report.queue_list_public),
                    "table_exists": _tri(report.table_exists),
                    "dfs_exists": _tri(report.dfs_exists),
                    "static_website": report.static_website or None,
                    "first_seen_url": _first_seen(account_targets, report.account),
                    "probes": report.summary,
                }
            )
        )

    # Only surface containers where we got a signal (public listing or
    # 200 metadata). ``public_access_level == ""`` + no 200 metadata +
    # list denied is treated as "nothing to see" noise.
    for container_report in container_reports:
        if not _container_interesting(container_report):
            continue
        matching = [
            f for f in blob_secrets
            if f.get("account") == container_report.account
            and f.get("container") == container_report.container
        ]
        resources.append(
            drop_empty(
                {
                    "kind": "storage_container",
                    "id": f"{container_report.account}/{container_report.container}",
                    "name": container_report.container,
                    "account": container_report.account,
                    "public_list": _tri(container_report.public_list),
                    "public_access_level": container_report.public_access_level or None,
                    "metadata_public": _tri(container_report.metadata_200),
                    "blobs_listed": len(container_report.blob_keys) or None,
                    "probes": container_report.summary,
                    "secrets_found": matching or None,
                }
            )
        )

    for blob in sampled_blobs:
        resources.append(
            drop_empty(
                {
                    "kind": "storage_blob",
                    "id": f"{blob['account']}/{blob['container']}/{blob['key']}",
                    "name": blob["key"],
                    "account": blob["account"],
                    "container": blob["container"],
                    "size": blob.get("size"),
                    "bytes_scanned": blob.get("bytes_scanned"),
                    "secret_count": blob.get("secret_count") or None,
                }
            )
        )

    if sas_findings:
        resources.append(
            {
                "kind": "sas_token_summary",
                "id": "sas-tokens",
                "name": "sas_tokens",
                "count": len(sas_findings),
                "secrets_found": sas_findings,
            }
        )

    summary = crawl_summary_row(
        scope.target_url or "",
        stats,
        pages,
        secrets=crawl_secrets,
    )
    if summary:
        resources.append(summary)

    if bruteforce_candidates:
        existing = {r.account for r in account_reports if r.existence == "exists"}
        resources.append(
            {
                "kind": "bruteforce_summary",
                "id": "bruteforce",
                "name": "bruteforce",
                "candidates": len(bruteforce_candidates),
                "matched": sum(1 for name in bruteforce_candidates if name in existing),
            }
        )
    return resources


def _container_interesting(report: ContainerProbeReport) -> bool:
    """True when the container probe produced actionable info."""
    if report.public_list:
        return True
    if report.metadata_200:
        return True
    if report.public_access_level and report.public_access_level != "none":
        return True
    return False


def _summarise(
    scope: StorageUnauthScope,
    account_targets: list[AccountHit],
    account_reports: list[StorageProbeReport],
    container_reports: list[ContainerProbeReport],
    sampled_blobs: list[dict[str, Any]],
    blob_secrets: list[dict[str, Any]],
    crawl_secrets: list[dict[str, Any]],
    sas_findings: list[dict[str, Any]],
    bruteforce_candidates: list[str],
) -> dict[str, Any]:
    existing = [r for r in account_reports if r.existence == "exists"]
    return {
        "target_url": scope.target_url or "(direct)",
        "accounts_probed": len(account_targets),
        "accounts_existing": len(existing),
        "blob_list_public_accounts": sum(1 for r in existing if r.blob_list_public),
        "file_list_public_accounts": sum(1 for r in existing if r.file_list_public),
        "queue_list_public_accounts": sum(1 for r in existing if r.queue_list_public),
        "static_website_accounts": sum(1 for r in existing if r.static_website),
        "containers_probed": len(container_reports),
        "public_containers": sum(1 for c in container_reports if c.public_list),
        "blobs_sampled": len(sampled_blobs),
        "blob_secrets": len(blob_secrets),
        "sas_tokens_leaked": len(sas_findings),
        "bundle_secrets": len(crawl_secrets),
        "bruteforce_candidates": len(bruteforce_candidates),
    }


def _render_verdict(
    console,
    scope: StorageUnauthScope,
    account_reports: list[StorageProbeReport],
    container_reports: list[ContainerProbeReport],
    blob_secrets: list[dict[str, Any]],
    crawl_secrets: list[dict[str, Any]],
    sas_findings: list[dict[str, Any]],
) -> None:
    if not account_reports:
        console.print(
            Panel(
                "No storage accounts probed — supply --url, --account, or --bruteforce.",
                title="verdict",
                border_style="warning",
            )
        )
        return

    existing = [r for r in account_reports if r.existence == "exists"]
    severity = "info"
    lines: list[str] = [
        f"[success]{len(existing)}[/success] of {len(account_reports)} "
        "probed storage account(s) exist."
    ]
    public_containers = [c for c in container_reports if c.public_list]
    if public_containers:
        lines.append(
            f"[error]{len(public_containers)}[/error] container(s) allow "
            "unauthenticated listing:"
            + "".join(
                f"\n  • {c.account}/{c.container} ({len(c.blob_keys)} blobs shown)"
                for c in public_containers
            )
        )
        severity = "error"
    if blob_secrets:
        lines.append(
            f"[error]{len(blob_secrets)}[/error] credential match(es) "
            "inside public blob bodies."
        )
        severity = "error"
    if sas_findings:
        lines.append(
            f"[error]{len(sas_findings)}[/error] leaked SAS token(s) in crawled web bundles."
        )
        severity = "error"
    if crawl_secrets:
        lines.append(
            f"[error]{len(crawl_secrets)}[/error] credential match(es) "
            "in crawled web bundles."
        )
        severity = "error"
    console.print(Panel("\n".join(lines), title="verdict", border_style=severity))
    _ = scope


def _tri(value: bool | None) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "-"


def _first_seen(targets: list[AccountHit], account: str) -> str:
    for hit in targets:
        if hit.name == account:
            return hit.first_seen_url
    return ""


def _finalise_service(
    name: str,
    svc_started: datetime,
    resources: list[dict[str, Any]],
    cis_fields: dict[str, Any],
    errors: list[str],
) -> ServiceResult:
    service = ServiceResult(
        provider=Provider.AZURE,
        service=name,
        started_at=svc_started,
        resources=resources,
        cis_fields=cis_fields,
        errors=errors,
    )
    finished = datetime.now(timezone.utc)
    service.finished_at = finished
    service.duration_s = round((finished - svc_started).total_seconds(), 3)
    return service


def _finalise_run(
    started: datetime,
    cse_scope: Any,
    identity: dict[str, Any],
    service: ServiceResult,
) -> EnumerationRun:
    finished = datetime.now(timezone.utc)
    return EnumerationRun(
        provider=Provider.AZURE,
        scope=cse_scope,
        identity=identity,
        services=[service],
        started_at=started,
        finished_at=finished,
        duration_s=round((finished - started).total_seconds(), 3),
    )
