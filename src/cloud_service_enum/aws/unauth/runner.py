"""Orchestrates the unauthenticated AWS recon runs.

Every runner here follows the same pattern: optional web-app crawl →
service-specific regex extraction + direct targets → public-API probes
→ one :class:`EnumerationRun` rendered by the shared Rich helpers and
piped through the standard report writers.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from rich.panel import Panel

from cloud_service_enum.aws.unauth.api_gateway import (
    ApiHit,
    classify_direct_api_url,
    extract_endpoints,
    probe_api_root,
    probe_cors,
    probe_lambda_url,
    probe_openapi_leaks,
    probe_stages,
)
from cloud_service_enum.aws.unauth.cognito import (
    CognitoHit,
    ProbeResult,
    extract,
    probe_get_id,
    probe_initiate_auth,
    probe_signup,
)
from cloud_service_enum.aws.unauth.common import (
    SHARED_CRAWL_DEFAULTS,
    build_cse_scope,
    crawl_errors,
    crawl_if_url,
    crawl_summary_row,
    drop_empty,
    render_preamble,
    scan_pages_for_secrets,
    scope_hosts,
)
from cloud_service_enum.aws.unauth.crawler import DEFAULT_USER_AGENT, FetchedPage
from cloud_service_enum.aws.unauth.s3 import (
    BucketHit,
    BucketProbeReport,
    bruteforce_names,
    download_public_objects,
    extract_buckets,
    load_default_suffix_wordlist,
    probe_bucket,
    scan_public_objects,
)
from cloud_service_enum.core.display import render_service, render_summary
from cloud_service_enum.core.loot import loot_destination
from cloud_service_enum.core.models import EnumerationRun, Provider, ServiceResult
from cloud_service_enum.core.output import get_console


# ---------------------------------------------------------------------------
# Cognito
# ---------------------------------------------------------------------------


@dataclass
class CognitoUnauthScope:
    """Inputs for ``cse aws unauth cognito``."""

    target_url: str
    max_pages: int = SHARED_CRAWL_DEFAULTS["max_pages"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()
    probe: bool = True
    probe_signup: bool = False


async def run_cognito_unauth(scope: CognitoUnauthScope) -> EnumerationRun:
    """Crawl the target, extract Cognito IDs, optionally probe."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope("unauth-cognito", scope.max_concurrency, scope.timeout_s)
    identity_label = urlparse(scope.target_url).netloc or scope.target_url
    identity = render_preamble(
        console,
        service_label="unauth-cognito",
        cse_scope=cse_scope,
        identity_label=identity_label,
        extras={
            "Target URL": scope.target_url,
            "Max pages": scope.max_pages,
            "Probes": "on" if scope.probe else "off",
            "SignUp probe": "on (opt-in)" if scope.probe_signup else "off",
            "In-scope hosts": ", ".join(scope_hosts(scope.target_url, scope.extra_hosts))
            or "(start host)",
        },
    )

    svc_started = datetime.now(timezone.utc)
    pages, stats = await crawl_if_url(
        scope.target_url,
        max_pages=scope.max_pages,
        max_concurrency=scope.max_concurrency,
        timeout_s=scope.timeout_s,
        user_agent=scope.user_agent,
        extra_hosts=tuple(scope.extra_hosts),
    )
    hits = extract(pages)
    secret_findings = scan_pages_for_secrets(pages)

    probe_results: dict[str, list[ProbeResult]] = {}
    errors = crawl_errors(scope.target_url, pages)
    if scope.probe:
        async with httpx.AsyncClient(
            timeout=scope.timeout_s,
            headers={"User-Agent": scope.user_agent},
        ) as client:
            probe_results = await _run_cognito_probes(client, hits, scope.probe_signup)

    resources = _build_cognito_resources(
        scope, pages, stats, hits, probe_results, secret_findings
    )
    cis_fields = _summarise_cognito(scope, stats, hits, probe_results, secret_findings)

    service = _finalise_service(
        "unauth-cognito", svc_started, resources, cis_fields, errors
    )
    run = _finalise_run(started, cse_scope, identity, service)

    render_service(console, service)
    _render_cognito_verdict(console, scope, hits, probe_results, secret_findings)
    render_summary(console, run)
    return run


async def _run_cognito_probes(
    client: httpx.AsyncClient,
    hits: list[CognitoHit],
    do_signup: bool,
) -> dict[str, list[ProbeResult]]:
    """Run every probe applicable to ``hits``, keyed by pool/client id."""
    user_pools = [h for h in hits if h.kind == "user_pool"]
    identity_pools = [h for h in hits if h.kind == "identity_pool"]
    client_ids = [h for h in hits if h.kind == "client_id"]

    results: dict[str, list[ProbeResult]] = {}
    tasks: list[tuple[str, asyncio.Task[ProbeResult]]] = []

    for pool in identity_pools:
        tasks.append(
            (pool.value, asyncio.create_task(probe_get_id(client, pool.value)))
        )

    for pool in user_pools:
        for cid in client_ids:
            if cid.region and cid.region != pool.region:
                continue
            tasks.append(
                (
                    pool.value,
                    asyncio.create_task(
                        probe_initiate_auth(client, pool.value, cid.value)
                    ),
                )
            )
            if do_signup:
                tasks.append(
                    (
                        pool.value,
                        asyncio.create_task(
                            probe_signup(client, pool.value, cid.value)
                        ),
                    )
                )

    for owner, task in tasks:
        try:
            result = await task
        except Exception as exc:  # noqa: BLE001
            result = ProbeResult("probe", "error", f"{exc.__class__.__name__}: {exc}")
        results.setdefault(owner, []).append(result)
    return results


def _build_cognito_resources(
    scope: CognitoUnauthScope,
    pages: list[FetchedPage],
    stats: Any,
    hits: list[CognitoHit],
    probes: dict[str, list[ProbeResult]],
    secrets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    user_pools = [h for h in hits if h.kind == "user_pool"]
    identity_pools = [h for h in hits if h.kind == "identity_pool"]
    client_ids = [h for h in hits if h.kind == "client_id"]
    resources: list[dict[str, Any]] = []

    for pool in user_pools:
        related_clients = [
            c.value for c in client_ids if not c.region or c.region == pool.region
        ]
        results = probes.get(pool.value, [])
        resources.append(
            drop_empty(
                {
                    "kind": "user_pool",
                    "id": pool.value,
                    "region": pool.region,
                    "client_ids": ", ".join(related_clients) or "-",
                    "first_seen_url": pool.first_seen_url,
                    "auth_flows": _maybe_auth_flow_summary(results),
                    "signup_enabled": _maybe_signup(results),
                    "probes": _summarise_probe_messages(results),
                }
            )
        )

    for pool in identity_pools:
        results = probes.get(pool.value, [])
        resources.append(
            drop_empty(
                {
                    "kind": "identity_pool",
                    "id": pool.value,
                    "region": pool.region,
                    "first_seen_url": pool.first_seen_url,
                    "unauth_allowed": _maybe_unauth(results),
                    "sample_identity_id": _maybe_sample_identity(results),
                    "probes": _summarise_probe_messages(results),
                }
            )
        )

    if not user_pools and not identity_pools:
        for cid in client_ids:
            resources.append(
                {
                    "kind": "client_id",
                    "id": cid.value,
                    "region": cid.region or "-",
                    "first_seen_url": cid.first_seen_url,
                }
            )

    summary = crawl_summary_row(scope.target_url, stats, pages, secrets=secrets)
    if summary:
        resources.append(summary)
    return resources


def _summarise_cognito(
    scope: CognitoUnauthScope,
    stats: Any,
    hits: list[CognitoHit],
    probes: dict[str, list[ProbeResult]],
    secrets: list[dict[str, Any]],
) -> dict[str, Any]:
    user_pools = [h for h in hits if h.kind == "user_pool"]
    identity_pools = [h for h in hits if h.kind == "identity_pool"]
    client_ids = [h for h in hits if h.kind == "client_id"]
    unauth_pools = sum(
        1
        for results in probes.values()
        for r in results
        if r.name == "GetId" and r.status == "ok"
    )
    signup_enabled = sum(
        1
        for results in probes.values()
        for r in results
        if r.name == "SignUp" and r.detail.get("signup_enabled")
    )
    return {
        "target_url": scope.target_url,
        "pages_crawled": stats.pages_fetched,
        "js_files": stats.js_files,
        "user_pools": len(user_pools),
        "identity_pools": len(identity_pools),
        "app_client_ids": len(client_ids),
        "unauth_identity_pools": unauth_pools,
        "signup_enabled_pools": signup_enabled,
        "secrets_found": len(secrets),
    }


def _render_cognito_verdict(
    console,
    scope: CognitoUnauthScope,
    hits: list[CognitoHit],
    probes: dict[str, list[ProbeResult]],
    secrets: list[dict[str, Any]],
) -> None:
    if not hits and not secrets:
        console.print(
            Panel(
                f"No Cognito IDs found at [bold]{scope.target_url}[/bold].\n"
                "The crawl finished cleanly but nothing matched the user-pool, "
                "identity-pool or client-id patterns.",
                title="verdict",
                border_style="warning",
            )
        )
        return

    lines: list[str] = []
    user_pools = [h for h in hits if h.kind == "user_pool"]
    identity_pools = [h for h in hits if h.kind == "identity_pool"]
    client_ids = [h for h in hits if h.kind == "client_id"]
    if user_pools:
        lines.append(
            f"[success]{len(user_pools)}[/success] user pool(s) — "
            + ", ".join(p.value for p in user_pools)
        )
    if identity_pools:
        lines.append(
            f"[success]{len(identity_pools)}[/success] identity pool(s) — "
            + ", ".join(p.value for p in identity_pools)
        )
    if client_ids:
        lines.append(
            f"[success]{len(client_ids)}[/success] app client id(s) — "
            + ", ".join(c.value for c in client_ids)
        )

    severity = "info"
    if any(
        r.name == "GetId" and r.status == "ok"
        for results in probes.values()
        for r in results
    ):
        lines.append(
            "[error]One or more identity pools issue unauthenticated identities.[/error]"
        )
        severity = "error"
    if any(
        r.name == "SignUp" and r.detail.get("signup_enabled")
        for results in probes.values()
        for r in results
    ):
        lines.append(
            "[error]Self-registration is enabled on at least one user pool.[/error]"
        )
        severity = "error"
    if secrets:
        lines.append(
            f"[error]{len(secrets)}[/error] credential pattern(s) matched in crawled bodies."
        )
        severity = "error"

    console.print(Panel("\n".join(lines), title="verdict", border_style=severity))


def _maybe_signup(results: list[ProbeResult]) -> str | None:
    for r in results:
        if r.name == "SignUp" and r.detail:
            return "yes" if r.detail.get("signup_enabled") else "no"
    return None


def _maybe_auth_flow_summary(results: list[ProbeResult]) -> str | None:
    parts: list[str] = []
    for r in results:
        if r.name != "InitiateAuth" or not r.detail:
            continue
        if r.detail.get("user_password_auth_enabled") is True:
            parts.append("USER_PASSWORD_AUTH")
        elif r.detail.get("user_password_auth_enabled") is False:
            parts.append("no USER_PASSWORD_AUTH")
        elif r.detail.get("client_id_valid") is False:
            parts.append("invalid client")
    return ", ".join(parts) if parts else None


def _maybe_unauth(results: list[ProbeResult]) -> str | None:
    for r in results:
        if r.name == "GetId":
            if r.status == "ok":
                return "yes"
            if r.status == "denied":
                return "no"
    return None


def _maybe_sample_identity(results: list[ProbeResult]) -> str | None:
    for r in results:
        if r.name == "GetId" and r.detail.get("identity_id"):
            return str(r.detail["identity_id"])
    return None


def _summarise_probe_messages(results: list[ProbeResult]) -> str | None:
    if not results:
        return None
    return " · ".join(f"{r.name}: {r.message}" for r in results)


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------


@dataclass
class S3UnauthScope:
    """Inputs for ``cse aws unauth s3``."""

    target_url: str | None = None
    buckets: tuple[str, ...] = ()
    bruteforce: bool = False
    bruteforce_prefixes: tuple[str, ...] = ()
    bruteforce_wordlist: Path | None = None
    max_objects: int = 100
    max_object_size_kb: int = 500
    download: bool = False
    download_all: bool = False
    download_files: tuple[str, ...] = ()
    max_pages: int = SHARED_CRAWL_DEFAULTS["max_pages"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()


async def run_s3_unauth(scope: S3UnauthScope) -> EnumerationRun:
    """Crawl (optional) + probe each discovered / supplied S3 bucket."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope("unauth-s3", scope.max_concurrency, scope.timeout_s)
    identity_label = (
        urlparse(scope.target_url).netloc if scope.target_url else "(bucket list)"
    )

    pages, stats = await crawl_if_url(
        scope.target_url,
        max_pages=scope.max_pages,
        max_concurrency=scope.max_concurrency,
        timeout_s=scope.timeout_s,
        user_agent=scope.user_agent,
        extra_hosts=tuple(scope.extra_hosts),
    )
    crawl_hits = extract_buckets(pages) if pages else []
    secret_findings = scan_pages_for_secrets(pages)

    suffixes: list[str] = []
    if scope.bruteforce:
        if scope.bruteforce_wordlist is not None:
            suffixes = [
                line.strip()
                for line in scope.bruteforce_wordlist.read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        else:
            suffixes = load_default_suffix_wordlist()

    bruteforce_candidates = list(
        bruteforce_names(scope.bruteforce_prefixes, suffixes)
    ) if scope.bruteforce else []

    targets = _merge_bucket_targets(crawl_hits, scope.buckets, bruteforce_candidates)

    render_preamble(
        console,
        service_label="unauth-s3",
        cse_scope=cse_scope,
        identity_label=identity_label or "(unknown)",
        extras={
            "Target URL": scope.target_url or "(none)",
            "Buckets (direct)": ", ".join(scope.buckets) or "(none)",
            "Bruteforce": f"{len(bruteforce_candidates)} candidates"
            if bruteforce_candidates
            else "off",
            "Max objects / bucket": scope.max_objects,
            "Max object size (KB)": scope.max_object_size_kb,
            "Total candidates": len(targets),
        },
    )

    svc_started = datetime.now(timezone.utc)
    reports: list[BucketProbeReport] = []
    sampled_objects: list[dict[str, Any]] = []
    downloaded_objects: list[dict[str, Any]] = []
    bucket_secrets: list[dict[str, Any]] = []
    errors = crawl_errors(scope.target_url, pages)

    if targets:
        sem = asyncio.Semaphore(scope.max_concurrency)
        async with httpx.AsyncClient(
            timeout=scope.timeout_s,
            headers={"User-Agent": scope.user_agent},
        ) as client:
            reports = await asyncio.gather(
                *[_probe_bucket_with_sem(client, sem, hit) for hit in targets]
            )
            # Sample + secret-scan public buckets in a second wave.
            for report in reports:
                if not report.public_list or not report.object_keys:
                    continue
                sampled, report_secrets = await scan_public_objects(
                    client,
                    report.bucket,
                    report.region,
                    report.object_keys,
                    max_objects=scope.max_objects,
                    max_object_size_kb=scope.max_object_size_kb,
                )
                sampled_objects.extend(sampled)
                bucket_secrets.extend(report_secrets)
                if scope.download:
                    selected = _pick_download_keys(
                        report.object_keys,
                        scope.download_all,
                        scope.download_files,
                    )
                    for item in await download_public_objects(
                        client,
                        report.bucket,
                        report.region,
                        selected,
                    ):
                        destination = loot_destination(owner=report.bucket, key=item["key"])
                        destination.write_bytes(item["content"])
                        downloaded_objects.append(
                            {
                                "bucket": report.bucket,
                                "key": item["key"],
                                "bytes": item["bytes"],
                                "path": str(destination),
                            }
                        )

    resources = _build_s3_resources(
        scope,
        targets,
        reports,
        sampled_objects,
        downloaded_objects,
        bucket_secrets,
        pages,
        stats,
        secret_findings,
        bruteforce_candidates,
    )
    cis_fields = _summarise_s3(
        scope,
        targets,
        reports,
        sampled_objects,
        downloaded_objects,
        bucket_secrets,
        secret_findings,
        bruteforce_candidates,
    )

    service = _finalise_service(
        "unauth-s3", svc_started, resources, cis_fields, errors
    )
    identity = build_identity_dict(identity_label)
    run = _finalise_run(started, cse_scope, identity, service)

    render_service(console, service)
    _render_s3_verdict(console, scope, reports, bucket_secrets, secret_findings)
    render_summary(console, run)
    return run


async def _probe_bucket_with_sem(
    client: httpx.AsyncClient, sem: asyncio.Semaphore, hit: BucketHit
) -> BucketProbeReport:
    async with sem:
        return await probe_bucket(client, hit)


def _merge_bucket_targets(
    crawl_hits: list[BucketHit],
    direct: tuple[str, ...],
    bruteforce_candidates: list[str],
) -> list[BucketHit]:
    """Combine crawl/direct/bruteforce inputs into a unique list of hits."""
    seen: dict[str, BucketHit] = {}
    for hit in crawl_hits:
        seen.setdefault(hit.name, hit)
    for name in direct:
        cleaned = name.strip().lower()
        if cleaned and cleaned not in seen:
            seen[cleaned] = BucketHit(name=cleaned, region_hint="", first_seen_url="(--bucket)")
    for name in bruteforce_candidates:
        cleaned = name.strip().lower()
        if cleaned and cleaned not in seen:
            seen[cleaned] = BucketHit(
                name=cleaned, region_hint="", first_seen_url="(bruteforce)"
            )
    return list(seen.values())


def _pick_download_keys(
    keys: list[str],
    download_all: bool,
    download_files: tuple[str, ...],
) -> list[str]:
    if download_all:
        return list(keys)
    if not download_files:
        return []
    wanted = set(download_files)
    return [key for key in keys if key in wanted]


def _build_s3_resources(
    scope: S3UnauthScope,
    targets: list[BucketHit],
    reports: list[BucketProbeReport],
    sampled_objects: list[dict[str, Any]],
    downloaded_objects: list[dict[str, Any]],
    bucket_secrets: list[dict[str, Any]],
    pages: list[FetchedPage],
    stats: Any,
    crawl_secrets: list[dict[str, Any]],
    bruteforce_candidates: list[str],
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for report in reports:
        # Only surface confirmed-existing buckets. Bruteforce waves
        # generate a lot of ``no_such_bucket`` and TLS ``ConnectError``
        # noise (names containing ``.`` break AWS' wildcard cert, so
        # ``victim.api.s3.amazonaws.com`` never gets a valid handshake);
        # neither is actionable. Summary counters still see everything.
        if report.existence != "exists":
            continue
        matching = bucket_secrets_for(bucket_secrets, report.bucket)
        resources.append(
            drop_empty(
                {
                    "kind": "bucket",
                    "id": report.bucket,
                    "name": report.bucket,
                    "region": report.region or "-",
                    "public_list": _tri(report.public_list),
                    "public_acl": _tri(report.public_acl),
                    "public_policy": _tri(report.public_policy),
                    "public_website": _tri(report.public_website),
                    "public_cors": _tri(report.public_cors),
                    "objects_sampled": len(
                        [o for o in sampled_objects if o.get("bucket") == report.bucket]
                    ) or None,
                    "first_seen_url": _first_seen(targets, report.bucket),
                    "probes": report.summary,
                    "secrets_found": matching or None,
                }
            )
        )

    for obj in sampled_objects:
        resources.append(
            drop_empty(
                {
                    "kind": "bucket_object",
                    "id": f"{obj['bucket']}/{obj['key']}",
                    "name": obj["key"],
                    "bucket": obj["bucket"],
                    "size": obj.get("size"),
                    "bytes_scanned": obj.get("bytes_scanned"),
                    "secret_count": obj.get("secret_count") or None,
                }
            )
        )
    for obj in downloaded_objects:
        resources.append(
            {
                "kind": "downloaded_object",
                "id": f"{obj['bucket']}/{obj['key']}",
                "name": obj["key"],
                "bucket": obj["bucket"],
                "bytes": obj["bytes"],
                "loot_path": obj["path"],
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
        existing = {r.bucket for r in reports if r.existence == "exists"}
        resources.append(
            {
                "kind": "bruteforce_summary",
                "id": "bruteforce",
                "name": "bruteforce",
                "candidates": len(bruteforce_candidates),
                "matched": sum(
                    1 for name in bruteforce_candidates if name in existing
                ),
            }
        )
    return resources


def _summarise_s3(
    scope: S3UnauthScope,
    targets: list[BucketHit],
    reports: list[BucketProbeReport],
    sampled_objects: list[dict[str, Any]],
    downloaded_objects: list[dict[str, Any]],
    bucket_secrets: list[dict[str, Any]],
    crawl_secrets: list[dict[str, Any]],
    bruteforce_candidates: list[str],
) -> dict[str, Any]:
    existing = [r for r in reports if r.existence == "exists"]
    public_list = sum(1 for r in reports if r.public_list)
    return {
        "target_url": scope.target_url or "(direct)",
        "buckets_probed": len(targets),
        "buckets_existing": len(existing),
        "public_list_buckets": public_list,
        "public_acl_buckets": sum(1 for r in reports if r.public_acl),
        "public_policy_buckets": sum(1 for r in reports if r.public_policy),
        "objects_sampled": len(sampled_objects),
        "objects_downloaded": len(downloaded_objects),
        "bucket_object_secrets": len(bucket_secrets),
        "bundle_secrets": len(crawl_secrets),
        "bruteforce_candidates": len(bruteforce_candidates),
    }


def _render_s3_verdict(
    console,
    scope: S3UnauthScope,
    reports: list[BucketProbeReport],
    bucket_secrets: list[dict[str, Any]],
    crawl_secrets: list[dict[str, Any]],
) -> None:
    if not reports:
        console.print(
            Panel(
                "No buckets probed — supply --url, --bucket, or --bruteforce.",
                title="verdict",
                border_style="warning",
            )
        )
        return

    public_list = [r for r in reports if r.public_list]
    existing = [r for r in reports if r.existence == "exists"]
    severity = "info"
    lines: list[str] = [
        f"[success]{len(existing)}[/success] of {len(reports)} probed bucket(s) exist."
    ]
    if public_list:
        lines.append(
            f"[error]{len(public_list)}[/error] bucket(s) allow unauthenticated listing:"
            + "".join(f"\n  • {r.bucket}" for r in public_list)
        )
        severity = "error"
    if bucket_secrets:
        lines.append(
            f"[error]{len(bucket_secrets)}[/error] credential match(es) inside public object bodies."
        )
        severity = "error"
    if crawl_secrets:
        lines.append(
            f"[error]{len(crawl_secrets)}[/error] credential match(es) in crawled web bundles."
        )
        severity = "error"
    console.print(Panel("\n".join(lines), title="verdict", border_style=severity))
    _ = scope  # reserved for future per-target context


def _tri(value: bool | None) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "-"


def _first_seen(targets: list[BucketHit], bucket: str) -> str:
    for hit in targets:
        if hit.name == bucket:
            return hit.first_seen_url
    return ""


def bucket_secrets_for(
    findings: list[dict[str, Any]], bucket: str
) -> list[dict[str, Any]]:
    return [f for f in findings if f.get("bucket") == bucket]


# ---------------------------------------------------------------------------
# API Gateway + Lambda Function URLs
# ---------------------------------------------------------------------------


@dataclass
class ApiGatewayUnauthScope:
    """Inputs for ``cse aws unauth api-gateway``."""

    target_url: str | None = None
    api_urls: tuple[str, ...] = ()
    max_pages: int = SHARED_CRAWL_DEFAULTS["max_pages"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()


@dataclass
class _ApiProbeOutcome:
    hit: ApiHit
    root_status: str = "unknown"
    root_message: str = ""
    auth_required: str | None = None
    stages_detected: list[str] = field(default_factory=list)
    openapi_exposed: bool = False
    openapi_paths: int = 0
    openapi_title: str | None = None
    openapi_body: str | None = None
    cors_wildcard: bool | None = None
    cors_credentials: bool | None = None
    lambda_auth_type: str | None = None
    probes: list[str] = field(default_factory=list)


async def run_api_gateway_unauth(
    scope: ApiGatewayUnauthScope,
) -> EnumerationRun:
    """Crawl (optional) + probe each discovered / supplied API Gateway URL."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope("unauth-apigw", scope.max_concurrency, scope.timeout_s)
    identity_label = (
        urlparse(scope.target_url).netloc
        if scope.target_url
        else "(direct api urls)"
    )

    pages, stats = await crawl_if_url(
        scope.target_url,
        max_pages=scope.max_pages,
        max_concurrency=scope.max_concurrency,
        timeout_s=scope.timeout_s,
        user_agent=scope.user_agent,
        extra_hosts=tuple(scope.extra_hosts),
    )
    crawl_hits = extract_endpoints(pages) if pages else []
    secret_findings = scan_pages_for_secrets(pages)

    hits = _merge_api_targets(crawl_hits, scope.api_urls)

    render_preamble(
        console,
        service_label="unauth-apigw",
        cse_scope=cse_scope,
        identity_label=identity_label or "(unknown)",
        extras={
            "Target URL": scope.target_url or "(none)",
            "API URLs (direct)": ", ".join(scope.api_urls) or "(none)",
            "Targets": len(hits),
            "In-scope hosts": ", ".join(scope_hosts(scope.target_url, scope.extra_hosts))
            or "(none)",
        },
    )

    svc_started = datetime.now(timezone.utc)
    outcomes: list[_ApiProbeOutcome] = []
    errors = crawl_errors(scope.target_url, pages)

    if hits:
        sem = asyncio.Semaphore(scope.max_concurrency)
        async with httpx.AsyncClient(
            timeout=scope.timeout_s,
            headers={"User-Agent": scope.user_agent},
            follow_redirects=False,
        ) as client:
            outcomes = await asyncio.gather(
                *[_probe_api_hit(client, sem, hit) for hit in hits]
            )

    resources = _build_api_resources(scope, hits, outcomes, pages, stats, secret_findings)
    cis_fields = _summarise_api(scope, hits, outcomes, secret_findings)

    service = _finalise_service(
        "unauth-apigw", svc_started, resources, cis_fields, errors
    )
    identity = build_identity_dict(identity_label)
    run = _finalise_run(started, cse_scope, identity, service)

    render_service(console, service)
    _render_api_verdict(console, scope, outcomes, secret_findings)
    render_summary(console, run)
    return run


async def _probe_api_hit(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    hit: ApiHit,
) -> _ApiProbeOutcome:
    async with sem:
        outcome = _ApiProbeOutcome(hit=hit)
        if hit.kind == "lambda_url":
            lambda_result = await probe_lambda_url(client, hit.url)
            outcome.lambda_auth_type = lambda_result.auth_type
            outcome.cors_wildcard = lambda_result.cors_wildcard
            outcome.cors_credentials = lambda_result.cors_credentials
            outcome.root_status = lambda_result.root_status
            outcome.root_message = lambda_result.root_message
            outcome.probes.append(f"Lambda URL: {lambda_result.summary}")
            return outcome

        if hit.kind == "websocket":
            outcome.root_status = "detected"
            outcome.root_message = "WebSocket endpoint — handshake not probed"
            outcome.probes.append("WebSocket: detected only")
            return outcome

        root = await probe_api_root(client, hit)
        outcome.root_status = root.status
        outcome.root_message = root.message
        outcome.auth_required = root.auth_required
        outcome.probes.append(f"GET /: {root.message}")

        cors = await probe_cors(client, hit.url)
        outcome.cors_wildcard = cors.wildcard
        outcome.cors_credentials = cors.credentials
        if cors.summary:
            outcome.probes.append(f"CORS: {cors.summary}")

        if hit.kind == "rest":
            stages = await probe_stages(client, hit)
            outcome.stages_detected = stages.detected
            if stages.summary:
                outcome.probes.append(f"Stages: {stages.summary}")

        openapi = await probe_openapi_leaks(client, hit)
        if openapi.exposed:
            outcome.openapi_exposed = True
            outcome.openapi_paths = openapi.path_count
            outcome.openapi_title = openapi.title
            outcome.openapi_body = openapi.body_snippet
            outcome.probes.append(
                f"OpenAPI: exposed at {openapi.exposed_at} "
                f"({openapi.path_count} paths)"
            )
        return outcome


def _merge_api_targets(
    crawl_hits: list[ApiHit],
    direct_urls: tuple[str, ...],
) -> list[ApiHit]:
    """Combine crawl + direct URL targets (classified by regex)."""
    seen: dict[str, ApiHit] = {}
    for hit in crawl_hits:
        seen.setdefault(hit.url, hit)
    for raw in direct_urls:
        cleaned = raw.strip()
        if not cleaned:
            continue
        classified = classify_direct_api_url(cleaned)
        if classified is None:
            continue
        seen.setdefault(classified.url, classified)
    return list(seen.values())


def _build_api_resources(
    scope: ApiGatewayUnauthScope,
    hits: list[ApiHit],
    outcomes: list[_ApiProbeOutcome],
    pages: list[FetchedPage],
    stats: Any,
    secrets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for o in outcomes:
        if o.hit.kind == "lambda_url":
            resources.append(
                drop_empty(
                    {
                        "kind": "lambda_function_url",
                        "id": o.hit.url,
                        "name": o.hit.alias_or_id,
                        "region": o.hit.region or "-",
                        "url": o.hit.url,
                        "auth_type": o.lambda_auth_type or "-",
                        "cors_wildcard": _tri(o.cors_wildcard),
                        "cors_credentials": _tri(o.cors_credentials),
                        "first_seen_url": o.hit.first_seen_url,
                        "probes": " · ".join(o.probes) or None,
                    }
                )
            )
            continue
        row: dict[str, Any] = {
            "kind": "api_gateway",
            "id": o.hit.url,
            "name": o.hit.alias_or_id,
            "region": o.hit.region or "-",
            "type": o.hit.kind,
            "url": o.hit.url,
            "auth_required": o.auth_required or "-",
            "stages_detected": ", ".join(o.stages_detected) or None,
            "openapi_exposed": "yes" if o.openapi_exposed else "no",
            "cors_wildcard": _tri(o.cors_wildcard),
            "cors_credentials": _tri(o.cors_credentials),
            "first_seen_url": o.hit.first_seen_url,
            "probes": " · ".join(o.probes) or None,
        }
        if o.openapi_exposed and o.openapi_body:
            row["definition"] = o.openapi_body
            row["definition_language"] = "json"
        if o.openapi_title:
            row["openapi_title"] = o.openapi_title
        if o.openapi_paths:
            row["openapi_paths"] = o.openapi_paths
        resources.append(drop_empty(row))

    summary = crawl_summary_row(
        scope.target_url or "",
        stats,
        pages,
        secrets=secrets,
    )
    if summary:
        resources.append(summary)
    _ = hits  # targets == outcomes by construction
    return resources


def _summarise_api(
    scope: ApiGatewayUnauthScope,
    hits: list[ApiHit],
    outcomes: list[_ApiProbeOutcome],
    crawl_secrets: list[dict[str, Any]],
) -> dict[str, Any]:
    openapi = sum(1 for o in outcomes if o.openapi_exposed)
    wildcard = sum(1 for o in outcomes if o.cors_wildcard is True)
    public_lambda = sum(
        1 for o in outcomes if o.hit.kind == "lambda_url" and o.lambda_auth_type == "NONE"
    )
    return {
        "target_url": scope.target_url or "(direct)",
        "apis_probed": len(hits),
        "rest_apis": sum(1 for h in hits if h.kind == "rest"),
        "http_apis": sum(1 for h in hits if h.kind == "http"),
        "websocket_apis": sum(1 for h in hits if h.kind == "websocket"),
        "lambda_urls": sum(1 for h in hits if h.kind == "lambda_url"),
        "openapi_exposed": openapi,
        "cors_wildcard": wildcard,
        "public_lambda_urls": public_lambda,
        "bundle_secrets": len(crawl_secrets),
    }


def _render_api_verdict(
    console,
    scope: ApiGatewayUnauthScope,
    outcomes: list[_ApiProbeOutcome],
    crawl_secrets: list[dict[str, Any]],
) -> None:
    if not outcomes:
        console.print(
            Panel(
                "No API Gateway endpoints or Lambda URLs probed — supply --url or --api-url.",
                title="verdict",
                border_style="warning",
            )
        )
        return

    severity = "info"
    lines: list[str] = [
        f"[success]{len(outcomes)}[/success] endpoint(s) probed."
    ]
    openapi = [o for o in outcomes if o.openapi_exposed]
    if openapi:
        lines.append(
            f"[error]{len(openapi)}[/error] endpoint(s) leak an OpenAPI/Swagger spec:"
            + "".join(f"\n  • {o.hit.url}" for o in openapi)
        )
        severity = "error"
    wildcard = [o for o in outcomes if o.cors_wildcard is True]
    if wildcard:
        lines.append(
            f"[error]{len(wildcard)}[/error] endpoint(s) send "
            "Access-Control-Allow-Origin: *."
        )
        severity = "error"
    public_lambda = [
        o for o in outcomes if o.hit.kind == "lambda_url" and o.lambda_auth_type == "NONE"
    ]
    if public_lambda:
        lines.append(
            f"[error]{len(public_lambda)}[/error] Lambda Function URL(s) are "
            "publicly callable (AUTH_TYPE=NONE)."
        )
        severity = "error"
    if crawl_secrets:
        lines.append(
            f"[error]{len(crawl_secrets)}[/error] credential match(es) in crawled web bundles."
        )
        severity = "error"
    console.print(Panel("\n".join(lines), title="verdict", border_style=severity))
    _ = scope


# ---------------------------------------------------------------------------
# Small shared helpers used by all three runners
# ---------------------------------------------------------------------------


def _finalise_service(
    name: str,
    svc_started: datetime,
    resources: list[dict[str, Any]],
    cis_fields: dict[str, Any],
    errors: list[str],
) -> ServiceResult:
    service = ServiceResult(
        provider=Provider.AWS,
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
        provider=Provider.AWS,
        scope=cse_scope,
        identity=identity,
        services=[service],
        started_at=started,
        finished_at=finished,
        duration_s=round((finished - started).total_seconds(), 3),
    )


def build_identity_dict(label: str) -> dict[str, Any]:
    """Mirror ``common.build_identity`` for callers that build a run manually."""
    return {
        "provider": Provider.AWS.value,
        "principal": "(unauthenticated)",
        "tenant_or_account": label,
        "auth_method": "none — public web crawl / probes",
    }
