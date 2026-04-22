"""Orchestrates an unauthenticated Cognito recon run.

The flow is:

1. Recursively crawl the entry URL (HTML + same-origin JS / JSON).
2. Regex-extract user-pool / identity-pool / app-client IDs from every
   text body. Stray AWS-style credentials in JS bundles are surfaced
   via :mod:`cloud_service_enum.core.secrets` so they appear under the
   normal ``secrets_found`` UI.
3. Optionally probe the public Cognito endpoints to characterise each
   discovered pool (auth flows, unauth identity issuance, self-signup).
4. Wrap the result in an :class:`EnumerationRun` so the existing
   terminal renderer + report writers handle it.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from rich.panel import Panel

from cloud_service_enum.aws.unauth.cognito import (
    CognitoHit,
    ProbeResult,
    extract,
    probe_get_id,
    probe_initiate_auth,
    probe_signup,
)
from cloud_service_enum.aws.unauth.crawler import (
    DEFAULT_USER_AGENT,
    CrawlScope,
    FetchedPage,
    crawl,
)
from cloud_service_enum.core.display import (
    render_config,
    render_identity,
    render_service,
    render_summary,
)
from cloud_service_enum.core.models import EnumerationRun, Provider, Scope, ServiceResult
from cloud_service_enum.core.output import get_console
from cloud_service_enum.core.secrets import scan_text


@dataclass
class CognitoUnauthScope:
    """Inputs for ``cse aws unauth cognito``."""

    target_url: str
    max_pages: int = 250
    max_concurrency: int = 10
    timeout_s: float = 15.0
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()
    probe: bool = True
    probe_signup: bool = False


async def run_cognito_unauth(scope: CognitoUnauthScope) -> EnumerationRun:
    """Crawl the target, extract Cognito IDs, optionally probe."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = Scope(
        provider=Provider.AWS,
        services=["unauth-cognito"],
        max_concurrency=scope.max_concurrency,
        timeout_s=scope.timeout_s,
        iam_policy_bodies=False,
    )
    identity = {
        "provider": Provider.AWS.value,
        "principal": "(unauthenticated)",
        "tenant_or_account": urlparse(scope.target_url).netloc or scope.target_url,
        "auth_method": "none — public web crawl",
    }
    render_identity(console, identity)
    render_config(
        console,
        Provider.AWS,
        cse_scope,
        extras={
            "Target URL": scope.target_url,
            "Max pages": scope.max_pages,
            "Probes": "on" if scope.probe else "off",
            "SignUp probe": "on (opt-in)" if scope.probe_signup else "off",
            "In-scope hosts": ", ".join(_scope_hosts(scope)) or "(start host)",
        },
    )

    svc_started = datetime.now(timezone.utc)
    crawl_scope = CrawlScope(
        start_url=scope.target_url,
        max_pages=scope.max_pages,
        max_concurrency=scope.max_concurrency,
        timeout_s=scope.timeout_s,
        user_agent=scope.user_agent,
        extra_hosts=tuple(scope.extra_hosts),
    )
    pages, stats = await crawl(crawl_scope)
    hits = extract(pages)
    secret_findings = _scan_pages_for_secrets(pages)

    probe_results: dict[str, list[ProbeResult]] = {}
    errors: list[str] = []
    if scope.probe:
        async with httpx.AsyncClient(
            timeout=scope.timeout_s,
            headers={"User-Agent": scope.user_agent},
        ) as client:
            probe_results = await _run_probes(client, hits, scope.probe_signup)

    for page in pages:
        if page.error and page.url == scope.target_url:
            errors.append(f"crawl: {page.url}: {page.error}")
            break

    resources = _build_resources(scope, pages, stats, hits, probe_results, secret_findings)
    cis_fields = _summarise(scope, stats, hits, probe_results, secret_findings)

    service = ServiceResult(
        provider=Provider.AWS,
        service="unauth-cognito",
        started_at=svc_started,
        resources=resources,
        cis_fields=cis_fields,
        errors=errors,
    )
    finished = datetime.now(timezone.utc)
    service.finished_at = finished
    service.duration_s = round((finished - svc_started).total_seconds(), 3)

    run = EnumerationRun(
        provider=Provider.AWS,
        scope=cse_scope,
        identity=identity,
        services=[service],
        started_at=started,
        finished_at=finished,
        duration_s=round((finished - started).total_seconds(), 3),
    )
    render_service(console, service)
    _render_verdict(console, scope, hits, probe_results, secret_findings)
    render_summary(console, run)
    return run


# ---------------------------------------------------------------------------
# Probe orchestration
# ---------------------------------------------------------------------------


async def _run_probes(
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


# ---------------------------------------------------------------------------
# Resource shaping
# ---------------------------------------------------------------------------


def _build_resources(
    scope: CognitoUnauthScope,
    pages: list[FetchedPage],
    stats: Any,
    hits: list[CognitoHit],
    probes: dict[str, list[ProbeResult]],
    secrets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Translate raw crawl/probe output into renderable resource dicts."""
    user_pools = [h for h in hits if h.kind == "user_pool"]
    identity_pools = [h for h in hits if h.kind == "identity_pool"]
    client_ids = [h for h in hits if h.kind == "client_id"]
    resources: list[dict[str, Any]] = []

    for pool in user_pools:
        related_clients = [
            c.value for c in client_ids if not c.region or c.region == pool.region
        ]
        results = probes.get(pool.value, [])
        signup_enabled = _maybe_signup(results)
        auth_flows = _maybe_auth_flow_summary(results)
        resources.append(
            _drop_empty(
                {
                    "kind": "user_pool",
                    "id": pool.value,
                    "region": pool.region,
                    "client_ids": ", ".join(related_clients) or "-",
                    "first_seen_url": pool.first_seen_url,
                    "auth_flows": auth_flows,
                    "signup_enabled": signup_enabled,
                    "probes": _summarise_probe_messages(results),
                }
            )
        )

    for pool in identity_pools:
        results = probes.get(pool.value, [])
        unauth = _maybe_unauth(results)
        sample = _maybe_sample_identity(results)
        resources.append(
            _drop_empty(
                {
                    "kind": "identity_pool",
                    "id": pool.value,
                    "region": pool.region,
                    "first_seen_url": pool.first_seen_url,
                    "unauth_allowed": unauth,
                    "sample_identity_id": sample,
                    "probes": _summarise_probe_messages(results),
                }
            )
        )

    if not user_pools and not identity_pools:
        # Surface client-id-only hits so the user can see something.
        for cid in client_ids:
            resources.append(
                {
                    "kind": "client_id",
                    "id": cid.value,
                    "region": cid.region or "-",
                    "first_seen_url": cid.first_seen_url,
                }
            )

    failed_pages = sum(1 for p in pages if p.error)
    summary_row: dict[str, Any] = {
        "kind": "crawl_summary",
        "id": scope.target_url,
        "name": urlparse(scope.target_url).netloc or scope.target_url,
        "pages_fetched": stats.pages_fetched,
        "js_files": stats.js_files,
        "kb_downloaded": round(stats.bytes_downloaded / 1024, 1),
        "hosts": ", ".join(sorted(stats.same_origin_hosts)),
        "failed_pages": failed_pages,
    }
    if secrets:
        summary_row["secrets_found"] = secrets
    resources.append(summary_row)

    return resources


def _maybe_signup(results: list[ProbeResult]) -> str | None:
    for r in results:
        if r.name == "SignUp" and r.detail:
            return "yes" if r.detail.get("signup_enabled") else "no"
    return None


def _maybe_auth_flow_summary(results: list[ProbeResult]) -> str | None:
    parts: list[str] = []
    for r in results:
        if r.name != "InitiateAuth":
            continue
        if not r.detail:
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


def _drop_empty(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if v not in (None, "")}


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------


def _scan_pages_for_secrets(pages: list[FetchedPage]) -> list[dict[str, Any]]:
    """Run the shared secret regexes over every JS / JSON / HTML body."""
    findings: list[dict[str, Any]] = []
    for page in pages:
        if not page.body:
            continue
        hits = scan_text(page.url, page.body)
        for hit in hits:
            findings.append(hit.as_dict())
    return findings


# ---------------------------------------------------------------------------
# Summary / verdict
# ---------------------------------------------------------------------------


def _summarise(
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
        1 for results in probes.values()
        for r in results if r.name == "GetId" and r.status == "ok"
    )
    signup_enabled = sum(
        1 for results in probes.values()
        for r in results if r.name == "SignUp" and r.detail.get("signup_enabled")
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


def _render_verdict(
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
        lines.append("[error]Self-registration is enabled on at least one user pool.[/error]")
        severity = "error"
    if secrets:
        lines.append(
            f"[error]{len(secrets)}[/error] credential pattern(s) matched in crawled bodies."
        )
        severity = "error"

    console.print(
        Panel(
            "\n".join(lines),
            title="verdict",
            border_style=severity,
        )
    )


def _scope_hosts(scope: CognitoUnauthScope) -> list[str]:
    base = urlparse(scope.target_url).netloc.lower()
    extras = [h.lower() for h in scope.extra_hosts]
    return sorted({base, *extras} - {""})
