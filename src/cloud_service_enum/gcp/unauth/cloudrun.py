"""Cloud Run (``*.run.app``) extraction + auth-posture fingerprinting.

Cloud Run services get a default Google-managed URL of the form
``https://<service>-<hash>-<region>.a.run.app``. Custom domains can
additionally resolve onto ``<something>.run.app``. This module extracts
both shapes from a crawl + direct ``--url`` input, then issues a single
HEAD + GET to classify each endpoint:

* 2xx / 3xx + ``x-cloud-trace-context`` → ``public`` (no IAM gating).
* 401 / 403 + ``x-cloud-trace-context`` → ``iam-gated`` (Cloud Run is
  up but invoker permission is enforced).
* Anything else → ``proxy`` (usually an upstream LB / Firebase Hosting
  domain pointing at a private service).

No mutation, GET only, body capped. The classifier leans on Cloud
Run's canonical headers (``x-cloud-trace-context``, ``x-goog-appengine-instance``)
to distinguish "really Cloud Run" from a misattributed ``.run.app``
host.
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

# ``<service>-<hash>-<region>.a.run.app`` is the canonical default.
# Custom domains (``foo.run.app``) do exist but are rarer.
_DEFAULT_RE = re.compile(
    r"\bhttps?://([a-z0-9][a-z0-9\-]*)-([a-z0-9]+)-([a-z0-9]+)\.a\.run\.app"
    r"(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)
_GENERIC_RE = re.compile(
    r"\bhttps?://([a-z0-9][a-z0-9\-\.]*)\.run\.app(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CloudRunHit:
    """One Cloud Run URL extracted from a crawl / direct input."""

    url: str
    service_name: str
    region_hint: str
    first_seen_url: str


@dataclass
class CloudRunReport:
    """Auth-posture outcome of a single Cloud Run URL."""

    url: str
    service_name: str
    region_hint: str
    auth_mode: str = "unknown"
    head_status: int = 0
    get_status: int = 0
    is_cloud_run: bool = False
    cloud_trace: str = ""
    body_snippet: str = ""
    fingerprint_headers: dict[str, str] = field(default_factory=dict)
    error: str = ""
    first_seen_url: str = ""


@dataclass
class CloudRunUnauthScope:
    """Inputs for ``cse gcp unauth cloudrun``."""

    target_url: str | None = None
    urls: tuple[str, ...] = ()
    max_pages: int = SHARED_CRAWL_DEFAULTS["max_pages"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()


def extract(pages: list[FetchedPage]) -> list[CloudRunHit]:
    """Extract Cloud Run URLs from every crawled body."""
    seen: dict[str, CloudRunHit] = {}
    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in _DEFAULT_RE.finditer(body):
            service = match.group(1).lower()
            region = match.group(3).lower()
            url = f"https://{service}-{match.group(2).lower()}-{region}.a.run.app"
            seen.setdefault(
                url,
                CloudRunHit(
                    url=url,
                    service_name=service,
                    region_hint=region,
                    first_seen_url=page.url,
                ),
            )
        for match in _GENERIC_RE.finditer(body):
            host = match.group(1).lower()
            if ".a.run.app" in f"https://{host}.run.app":
                # Already captured by _DEFAULT_RE.
                continue
            url = f"https://{host}.run.app"
            seen.setdefault(
                url,
                CloudRunHit(
                    url=url,
                    service_name=host.split(".")[0],
                    region_hint="",
                    first_seen_url=page.url,
                ),
            )
    return list(seen.values())


def classify_direct_url(raw: str) -> CloudRunHit | None:
    """Parse an explicit ``--url`` into a :class:`CloudRunHit`."""
    raw = raw.strip()
    match = _DEFAULT_RE.match(raw)
    if match:
        service = match.group(1).lower()
        region = match.group(3).lower()
        url = f"https://{service}-{match.group(2).lower()}-{region}.a.run.app"
        return CloudRunHit(
            url=url,
            service_name=service,
            region_hint=region,
            first_seen_url="(--url)",
        )
    match = _GENERIC_RE.match(raw)
    if match:
        host = match.group(1).lower()
        url = f"https://{host}.run.app"
        return CloudRunHit(
            url=url,
            service_name=host.split(".")[0],
            region_hint="",
            first_seen_url="(--url)",
        )
    return None


async def probe(
    client: httpx.AsyncClient, hit: CloudRunHit
) -> CloudRunReport:
    """Run a ``HEAD`` + ``GET`` pair against one Cloud Run URL."""
    report = CloudRunReport(
        url=hit.url,
        service_name=hit.service_name,
        region_hint=hit.region_hint,
        first_seen_url=hit.first_seen_url,
    )
    target = hit.url.rstrip("/") + "/"
    try:
        head = await client.head(target, follow_redirects=False)
    except httpx.HTTPError as exc:
        report.error = f"HEAD {exc.__class__.__name__}: {exc}"
        return report
    report.head_status = head.status_code
    report.cloud_trace = (head.headers.get("x-cloud-trace-context") or "").strip()

    try:
        resp = await client.get(target, follow_redirects=False)
    except httpx.HTTPError as exc:
        report.error = f"GET {exc.__class__.__name__}: {exc}"
        return report
    report.get_status = resp.status_code
    if not report.cloud_trace:
        report.cloud_trace = (resp.headers.get("x-cloud-trace-context") or "").strip()

    snippet = (resp.text or "")[:240]
    report.body_snippet = snippet

    fingerprint_keys = (
        "x-cloud-trace-context",
        "x-goog-appengine-instance",
        "server",
        "alt-svc",
    )
    report.fingerprint_headers = {
        k: resp.headers[k] for k in fingerprint_keys if k in resp.headers
    }
    report.is_cloud_run = bool(
        report.cloud_trace
        or any(
            "google" in v.lower() or "frontend" in v.lower()
            for v in report.fingerprint_headers.values()
        )
    )
    report.auth_mode = _classify_auth_mode(
        resp.status_code, snippet, report.is_cloud_run
    )
    return report


def _classify_auth_mode(status: int, snippet: str, is_cloud_run: bool) -> str:
    lowered = snippet.lower()
    if status in (200, 201, 202, 204, 301, 302, 307, 308):
        return "public"
    if status in (401, 403):
        if is_cloud_run:
            return "iam-gated"
        return "auth-required"
    if status == 404:
        return "public (no route at /)"
    if "forbidden" in lowered and is_cloud_run:
        return "iam-gated"
    return f"proxy ({status})"


async def run_cloudrun_unauth(scope: CloudRunUnauthScope) -> EnumerationRun:
    """Crawl (optional) + probe every Cloud Run URL."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope(
        Provider.GCP, "unauth-cloudrun", scope.max_concurrency, scope.timeout_s
    )
    identity_label = (
        urlparse(scope.target_url).netloc
        if scope.target_url
        else "(direct urls)"
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
    crawl_hits = extract(pages) if pages else []

    direct_hits: list[CloudRunHit] = []
    for raw in scope.urls:
        classified = classify_direct_url(raw)
        if classified is not None:
            direct_hits.append(classified)

    hits: dict[str, CloudRunHit] = {}
    for hit in (*crawl_hits, *direct_hits):
        hits.setdefault(hit.url, hit)
    targets = list(hits.values())

    identity = render_preamble(
        console,
        provider=Provider.GCP,
        service_label="unauth-cloudrun",
        cse_scope=cse_scope,
        identity_label=identity_label or "(unknown)",
        extras={
            "Target URL": scope.target_url or "(none)",
            "Direct URLs": ", ".join(scope.urls) or "(none)",
            "Targets": len(targets),
            "In-scope hosts": ", ".join(scope_hosts(scope.target_url, scope.extra_hosts))
            or "(none)",
        },
    )

    svc_started = datetime.now(timezone.utc)
    reports: list[CloudRunReport] = []
    errors = crawl_errors(scope.target_url, pages)

    if targets:
        sem = asyncio.Semaphore(scope.max_concurrency)

        async def _one(hit: CloudRunHit) -> CloudRunReport:
            async with sem:
                return await probe(client, hit)

        async with httpx.AsyncClient(
            timeout=scope.timeout_s,
            headers={"User-Agent": scope.user_agent},
            follow_redirects=False,
        ) as client:
            reports = await asyncio.gather(*[_one(hit) for hit in targets])

    resources = _build_resources(scope, reports, pages, stats, secret_findings)
    cis_fields = _summarise(scope, reports, secret_findings)

    service = ServiceResult(
        provider=Provider.GCP,
        service="unauth-cloudrun",
        started_at=svc_started,
        resources=resources,
        cis_fields=cis_fields,
        errors=errors,
    )
    finished = datetime.now(timezone.utc)
    service.finished_at = finished
    service.duration_s = round((finished - svc_started).total_seconds(), 3)

    run = EnumerationRun(
        provider=Provider.GCP,
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
    scope: CloudRunUnauthScope,
    reports: list[CloudRunReport],
    pages: list[FetchedPage],
    stats: Any,
    secret_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for report in reports:
        if report.error:
            continue
        resources.append(
            drop_empty(
                {
                    "kind": "cloudrun_service",
                    "id": report.url,
                    "name": report.service_name,
                    "url": report.url,
                    "region_hint": report.region_hint or "-",
                    "auth_mode": report.auth_mode,
                    "is_cloud_run": "yes" if report.is_cloud_run else "no",
                    "head_status": report.head_status or None,
                    "get_status": report.get_status or None,
                    "cloud_trace": report.cloud_trace or None,
                    "fingerprint_headers": report.fingerprint_headers or None,
                    "first_seen_url": report.first_seen_url,
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
    scope: CloudRunUnauthScope,
    reports: list[CloudRunReport],
    crawl_secrets: list[dict[str, Any]],
) -> dict[str, Any]:
    public = [r for r in reports if r.auth_mode.startswith("public")]
    iam = [r for r in reports if r.auth_mode == "iam-gated"]
    return {
        "target_url": scope.target_url or "(direct)",
        "urls_probed": len(reports),
        "public_services": len(public),
        "iam_gated_services": len(iam),
        "proxy_services": sum(
            1 for r in reports if r.auth_mode.startswith("proxy")
        ),
        "bundle_secrets": len(crawl_secrets),
    }


def _render_verdict(
    console,
    scope: CloudRunUnauthScope,
    reports: list[CloudRunReport],
    crawl_secrets: list[dict[str, Any]],
) -> None:
    if not reports:
        console.print(
            Panel(
                "No Cloud Run URLs probed — supply --url.",
                title="verdict",
                border_style="warning",
            )
        )
        return
    public = [r for r in reports if r.auth_mode.startswith("public")]
    iam = [r for r in reports if r.auth_mode == "iam-gated"]
    severity = "info"
    lines: list[str] = [
        f"[success]{len(reports)}[/success] Cloud Run URL(s) probed."
    ]
    if public:
        lines.append(
            f"[error]{len(public)}[/error] URL(s) respond publicly:"
            + "".join(f"\n  • {r.url}" for r in public)
        )
        severity = "error"
    if iam:
        lines.append(
            f"[success]{len(iam)}[/success] URL(s) are IAM-gated "
            "(service exists but invoker auth enforced)."
        )
    if crawl_secrets:
        lines.append(
            f"[error]{len(crawl_secrets)}[/error] credential match(es) "
            "in crawled web bundles."
        )
        severity = "error"
    console.print(Panel("\n".join(lines), title="verdict", border_style=severity))
    _ = scope
