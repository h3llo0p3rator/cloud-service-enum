"""Azure App Service (``*.azurewebsites.net``) extraction + leak probes.

Extracts App Service hostnames from crawled bodies and fires a small
battery of safe read probes:

* ``/robots933456.txt`` — always returns ``200`` on a live App Service
  (documented canary). Quick existence check.
* ``/.git/HEAD``, ``/.env``, ``/package.json``, ``/appsettings.json`` —
  common misconfig leaks.
* ``/api/siteextensions`` on the SCM (``.scm.azurewebsites.net``)
  companion host — non-``401`` responses indicate anonymous Kudu
  access.

Every request is anonymous, ``GET`` only, capped in body size and the
classifier distinguishes between "site exists" and "misconfig leak".
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from rich.panel import Panel

from cloud_service_enum.core.display import render_service, render_summary
from cloud_service_enum.core.models import EnumerationRun, Provider, ServiceResult
from cloud_service_enum.core.output import get_console
from cloud_service_enum.core.unauth.common import (
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
from cloud_service_enum.core.unauth.crawler import DEFAULT_USER_AGENT, FetchedPage

# App Service publishes two paired hostnames: the app itself
# (``<name>.azurewebsites.net``) and the deployment SCM site
# (``<name>.scm.azurewebsites.net``). ``<name>-staging``,
# ``<name>-<slot>`` and custom slots are all valid.
_APPSERVICE_HOST_RE = re.compile(
    r"\b([a-z0-9][a-z0-9\-]{0,58}[a-z0-9])"
    r"(\.scm)?\.azurewebsites\.net\b",
    re.IGNORECASE,
)

_CANARY_PATH = "/robots933456.txt"
_LEAK_PATHS: tuple[str, ...] = (
    "/.git/HEAD",
    "/.env",
    "/package.json",
    "/appsettings.json",
    "/web.config",
    "/wwwroot/.env",
)
_SCM_PROBE_PATH = "/api/siteextensions"

_MAX_BODY = 8 * 1024


@dataclass(frozen=True)
class AppServiceHit:
    """One App Service reference surfaced by crawling or direct input."""

    hostname: str
    scm_hostname: str
    site_name: str
    first_seen_url: str


@dataclass
class AppServiceProbeResult:
    """Outcome of a single probe path against one App Service hostname."""

    path: str
    status: int = 0
    length: int = 0
    leak_indicator: str = ""
    snippet: str = ""
    error: str = ""


@dataclass
class AppServiceReport:
    """Full probe outcome for one hostname + its SCM companion."""

    hostname: str
    scm_hostname: str
    site_name: str
    exists: bool = False
    kudu_anonymous: bool | None = None
    probes: list[AppServiceProbeResult] = field(default_factory=list)
    first_seen_url: str = ""


@dataclass
class AppServiceUnauthScope:
    """Inputs for ``cse azure unauth appservice``."""

    target_url: str | None = None
    hostnames: tuple[str, ...] = ()
    max_pages: int = SHARED_CRAWL_DEFAULTS["max_pages"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()


def extract_hostnames(pages: list[FetchedPage]) -> list[AppServiceHit]:
    """Deduplicated list of App Service + SCM hostnames."""
    seen: dict[str, AppServiceHit] = {}
    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in _APPSERVICE_HOST_RE.finditer(body):
            site = match.group(1).lower()
            hostname = f"{site}.azurewebsites.net"
            scm = f"{site}.scm.azurewebsites.net"
            seen.setdefault(
                hostname,
                AppServiceHit(
                    hostname=hostname,
                    scm_hostname=scm,
                    site_name=site,
                    first_seen_url=page.url,
                ),
            )
    return list(seen.values())


def classify_direct_hostname(raw: str) -> AppServiceHit | None:
    """Turn an explicit ``--hostname`` into a :class:`AppServiceHit`."""
    match = _APPSERVICE_HOST_RE.fullmatch(raw.strip().lower())
    if not match:
        return None
    site = match.group(1).lower()
    return AppServiceHit(
        hostname=f"{site}.azurewebsites.net",
        scm_hostname=f"{site}.scm.azurewebsites.net",
        site_name=site,
        first_seen_url="(--hostname)",
    )


async def probe(
    client: httpx.AsyncClient, hit: AppServiceHit
) -> AppServiceReport:
    """Issue every probe against one App Service hostname."""
    report = AppServiceReport(
        hostname=hit.hostname,
        scm_hostname=hit.scm_hostname,
        site_name=hit.site_name,
        first_seen_url=hit.first_seen_url,
    )
    canary = await _probe_path(client, hit.hostname, _CANARY_PATH)
    report.probes.append(canary)
    if canary.status == 200 and "user-agent:" in canary.snippet.lower():
        report.exists = True
    elif canary.status in (401, 403):
        # Azure still returns a banner for locked-down sites; treat as
        # existing since DNS resolved + TLS handshake succeeded.
        report.exists = True

    for path in _LEAK_PATHS:
        result = await _probe_path(client, hit.hostname, path)
        report.probes.append(result)
        if _looks_like_leak(path, result):
            result.leak_indicator = _leak_indicator(path, result)

    scm = await _probe_path(
        client, hit.scm_hostname, _SCM_PROBE_PATH, is_scm=True
    )
    report.probes.append(scm)
    if scm.status in (200, 302):
        report.kudu_anonymous = True
    elif scm.status in (401, 403):
        report.kudu_anonymous = False
    return report


async def _probe_path(
    client: httpx.AsyncClient,
    hostname: str,
    path: str,
    *,
    is_scm: bool = False,
) -> AppServiceProbeResult:
    url = f"https://{hostname}{path}"
    result = AppServiceProbeResult(path=f"{'scm:' if is_scm else ''}{path}")
    try:
        resp = await client.get(url, follow_redirects=False)
    except httpx.HTTPError as exc:
        result.error = f"{exc.__class__.__name__}: {exc}"
        return result
    body = resp.content[:_MAX_BODY] if resp.content else b""
    try:
        snippet = body.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        snippet = ""
    result.status = resp.status_code
    result.length = len(resp.content or b"")
    result.snippet = snippet[:400]
    return result


def _looks_like_leak(path: str, result: AppServiceProbeResult) -> bool:
    """True when a misconfig-probe response is likely a real leak."""
    if result.error or result.status != 200:
        return False
    lowered_path = path.lower()
    body = result.snippet.lower()
    if lowered_path.endswith("/head"):
        return body.startswith("ref:") or "refs/heads" in body
    if lowered_path.endswith(".env"):
        return "=" in body and any(
            marker in body
            for marker in ("secret", "password", "key", "token", "api")
        )
    if lowered_path.endswith(".json"):
        return body.lstrip().startswith("{")
    if lowered_path.endswith(".config"):
        return "<configuration" in body
    return False


def _leak_indicator(path: str, result: AppServiceProbeResult) -> str:
    length = result.length
    return f"HTTP 200 · {length} bytes · {path}"


async def run_appservice_unauth(
    scope: AppServiceUnauthScope,
) -> EnumerationRun:
    """Crawl (optional) + probe every App Service hostname."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope(
        Provider.AZURE, "unauth-appservice", scope.max_concurrency, scope.timeout_s
    )
    identity_label = (
        urlparse(scope.target_url).netloc
        if scope.target_url
        else "(direct hostnames)"
    )

    pages, stats = await crawl_if_url(
        scope.target_url,
        max_pages=scope.max_pages,
        max_concurrency=scope.max_concurrency,
        timeout_s=scope.timeout_s,
        user_agent=scope.user_agent,
        extra_hosts=tuple(scope.extra_hosts),
    )
    secret_findings = scan_pages_for_secrets(pages)
    crawl_hits = extract_hostnames(pages) if pages else []

    direct_hits: list[AppServiceHit] = []
    for raw in scope.hostnames:
        classified = classify_direct_hostname(raw)
        if classified is not None:
            direct_hits.append(classified)

    hits: dict[str, AppServiceHit] = {}
    for hit in (*crawl_hits, *direct_hits):
        hits.setdefault(hit.hostname, hit)
    targets = list(hits.values())

    identity = render_preamble(
        console,
        provider=Provider.AZURE,
        service_label="unauth-appservice",
        cse_scope=cse_scope,
        identity_label=identity_label or "(unknown)",
        extras={
            "Target URL": scope.target_url or "(none)",
            "Hostnames (direct)": ", ".join(scope.hostnames) or "(none)",
            "Targets": len(targets),
            "In-scope hosts": ", ".join(scope_hosts(scope.target_url, scope.extra_hosts))
            or "(none)",
        },
    )

    svc_started = datetime.now(timezone.utc)
    reports: list[AppServiceReport] = []
    errors = crawl_errors(scope.target_url, pages)

    if targets:
        sem = asyncio.Semaphore(scope.max_concurrency)

        async def _one(hit: AppServiceHit) -> AppServiceReport:
            async with sem:
                return await probe(client, hit)

        async with httpx.AsyncClient(
            timeout=scope.timeout_s,
            headers={"User-Agent": scope.user_agent},
            follow_redirects=False,
        ) as client:
            reports = await asyncio.gather(*[_one(hit) for hit in targets])

    resources = _build_resources(
        scope, reports, pages, stats, secret_findings
    )
    cis_fields = _summarise(scope, reports, secret_findings)

    service = ServiceResult(
        provider=Provider.AZURE,
        service="unauth-appservice",
        started_at=svc_started,
        resources=resources,
        cis_fields=cis_fields,
        errors=errors,
    )
    finished = datetime.now(timezone.utc)
    service.finished_at = finished
    service.duration_s = round((finished - svc_started).total_seconds(), 3)

    run = EnumerationRun(
        provider=Provider.AZURE,
        scope=cse_scope,
        identity=identity,
        services=[service],
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        duration_s=round((datetime.now(timezone.utc) - started).total_seconds(), 3),
    )

    render_service(console, service)
    _render_verdict(console, scope, reports, secret_findings)
    render_summary(console, run)
    return run


def _build_resources(
    scope: AppServiceUnauthScope,
    reports: list[AppServiceReport],
    pages: list[FetchedPage],
    stats: Any,
    secret_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for report in reports:
        if not report.exists and not any(
            p.leak_indicator for p in report.probes
        ):
            continue
        probe_results = [
            {
                "path": p.path,
                "status": p.status,
                "length": p.length,
                "leak_indicator": p.leak_indicator or None,
            }
            for p in report.probes
        ]
        resources.append(
            drop_empty(
                {
                    "kind": "azure_webapp",
                    "id": report.hostname,
                    "name": report.site_name,
                    "hostname": report.hostname,
                    "scm_hostname": report.scm_hostname,
                    "exists": "yes" if report.exists else "-",
                    "kudu_anonymous": _tri(report.kudu_anonymous),
                    "first_seen_url": report.first_seen_url,
                    "probe_results": probe_results,
                    "leaks": [
                        p.leak_indicator for p in report.probes if p.leak_indicator
                    ]
                    or None,
                }
            )
        )
    summary = crawl_summary_row(
        scope.target_url or "",
        stats,
        pages,
        secrets=secret_findings,
    )
    if summary:
        resources.append(summary)
    return resources


def _summarise(
    scope: AppServiceUnauthScope,
    reports: list[AppServiceReport],
    crawl_secrets: list[dict[str, Any]],
) -> dict[str, Any]:
    existing = [r for r in reports if r.exists]
    leaking = [r for r in reports if any(p.leak_indicator for p in r.probes)]
    kudu = [r for r in reports if r.kudu_anonymous]
    return {
        "target_url": scope.target_url or "(direct)",
        "hostnames_probed": len(reports),
        "hostnames_existing": len(existing),
        "hostnames_leaking": len(leaking),
        "kudu_anonymous": len(kudu),
        "bundle_secrets": len(crawl_secrets),
    }


def _render_verdict(
    console,
    scope: AppServiceUnauthScope,
    reports: list[AppServiceReport],
    crawl_secrets: list[dict[str, Any]],
) -> None:
    if not reports:
        console.print(
            Panel(
                "No App Service hostnames probed — supply --url or --hostname.",
                title="verdict",
                border_style="warning",
            )
        )
        return
    severity = "info"
    lines: list[str] = [
        f"[success]{sum(1 for r in reports if r.exists)}[/success] of "
        f"{len(reports)} hostname(s) confirmed live."
    ]
    leaking = [r for r in reports if any(p.leak_indicator for p in r.probes)]
    if leaking:
        lines.append(
            f"[error]{len(leaking)}[/error] hostname(s) leak sensitive "
            "paths:"
            + "".join(
                f"\n  • {r.hostname}: "
                + ", ".join(p.path for p in r.probes if p.leak_indicator)
                for r in leaking
            )
        )
        severity = "error"
    kudu = [r for r in reports if r.kudu_anonymous]
    if kudu:
        lines.append(
            f"[error]{len(kudu)}[/error] SCM site(s) allow anonymous Kudu "
            "endpoints."
        )
        severity = "error"
    if crawl_secrets:
        lines.append(
            f"[error]{len(crawl_secrets)}[/error] credential match(es) in "
            "crawled web bundles."
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
