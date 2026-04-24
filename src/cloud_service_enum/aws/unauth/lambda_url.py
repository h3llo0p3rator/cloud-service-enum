"""Lambda Function URL extraction + auth-mode fingerprinting.

The existing ``cse aws unauth api-gateway`` command already classifies
Lambda URLs that fall out of an API Gateway crawl; this module is the
dedicated, standalone entry point — it accepts direct ``--url`` targets
without requiring a site crawl and keeps the probe surface minimal
(one HEAD + one GET).

Auth-mode classification mirrors the API Gateway probe:

* 2xx / 3xx response to an anonymous ``GET /`` → ``AUTH_TYPE=NONE``
  (publicly invokable).
* 403 + ``x-amzn-RequestId`` header (or an SigV4 challenge message) →
  ``AUTH_TYPE=AWS_IAM``.
* 404 from the function, but only after the root hostname resolves →
  ``AUTH_TYPE=NONE`` with an empty default route.
* Anything else is surfaced as ``unknown`` with the raw status code.
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

from cloud_service_enum.aws.unauth.crawler import DEFAULT_USER_AGENT, FetchedPage
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

_LAMBDA_URL_RE = re.compile(
    r"\bhttps?://([a-z0-9]+)\.lambda-url\.([a-z0-9\-]+)\.on\.aws(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LambdaUrlHit:
    """One Lambda Function URL extracted from a crawl / direct input."""

    url: str
    function_hint: str
    region: str
    first_seen_url: str


@dataclass
class LambdaUrlProbeResult:
    """Outcome of the ``HEAD`` + ``GET`` probe pair."""

    url: str
    function_hint: str
    region: str
    auth_mode: str = "unknown"
    head_status: int = 0
    get_status: int = 0
    request_id: str = ""
    cors_wildcard: bool | None = None
    cors_credentials: bool | None = None
    body_snippet: str = ""
    error: str = ""
    probes: list[str] = field(default_factory=list)


def extract(pages: list[FetchedPage]) -> list[LambdaUrlHit]:
    """Extract Lambda Function URLs from every crawled body."""
    seen: dict[str, LambdaUrlHit] = {}
    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in _LAMBDA_URL_RE.finditer(body):
            alias = match.group(1).lower()
            region = match.group(2).lower()
            url = f"https://{alias}.lambda-url.{region}.on.aws"
            seen.setdefault(
                url,
                LambdaUrlHit(
                    url=url,
                    function_hint=alias,
                    region=region,
                    first_seen_url=page.url,
                ),
            )
    return list(seen.values())


def classify_direct_url(raw: str) -> LambdaUrlHit | None:
    """Parse an explicit ``--url`` string into a :class:`LambdaUrlHit`."""
    match = _LAMBDA_URL_RE.match(raw.strip())
    if not match:
        return None
    alias = match.group(1).lower()
    region = match.group(2).lower()
    url = f"https://{alias}.lambda-url.{region}.on.aws"
    return LambdaUrlHit(
        url=url,
        function_hint=alias,
        region=region,
        first_seen_url="(--url)",
    )


async def probe(
    client: httpx.AsyncClient, hit: LambdaUrlHit
) -> LambdaUrlProbeResult:
    """Probe ``hit`` with a single ``HEAD`` then a small ``GET``."""
    result = LambdaUrlProbeResult(
        url=hit.url,
        function_hint=hit.function_hint,
        region=hit.region,
    )
    target = hit.url.rstrip("/") + "/"
    try:
        head = await client.head(target, follow_redirects=False)
    except httpx.HTTPError as exc:
        result.error = f"HEAD {exc.__class__.__name__}: {exc}"
        return result
    result.head_status = head.status_code
    result.request_id = (head.headers.get("x-amzn-requestid") or "").strip()

    try:
        resp = await client.get(
            target,
            headers={"Origin": "https://example.invalid"},
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        result.error = f"GET {exc.__class__.__name__}: {exc}"
        return result

    result.get_status = resp.status_code
    if not result.request_id:
        result.request_id = (resp.headers.get("x-amzn-requestid") or "").strip()
    snippet = (resp.text or "")[:240]
    result.body_snippet = snippet

    allow_origin = (resp.headers.get("access-control-allow-origin") or "").strip()
    allow_creds = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()
    result.cors_wildcard = allow_origin == "*"
    result.cors_credentials = allow_creds == "true"

    result.auth_mode = _classify_auth_mode(resp.status_code, snippet, result.request_id)
    result.probes.append(
        f"HEAD {result.head_status} · GET {result.get_status} · AUTH={result.auth_mode}"
    )
    return result


def _classify_auth_mode(status: int, snippet: str, request_id: str) -> str:
    """Decide whether the URL is ``NONE`` or ``AWS_IAM`` (or unknown)."""
    lowered = snippet.lower()
    if status in (200, 201, 202, 204, 301, 302, 307, 308):
        return "NONE"
    if status == 404:
        return "NONE (no route at /)"
    if status == 403:
        if "missing authentication token" in lowered or (
            "the request signature" in lowered and "sigv4" in lowered
        ):
            return "AWS_IAM"
        if request_id:
            return "AWS_IAM"
        return "AWS_IAM"
    if status == 401:
        return "AWS_IAM"
    return f"unknown ({status})"


@dataclass
class LambdaUrlUnauthScope:
    """Inputs for ``cse aws unauth lambda-url``."""

    target_url: str | None = None
    urls: tuple[str, ...] = ()
    max_pages: int = SHARED_CRAWL_DEFAULTS["max_pages"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()


async def run_lambda_url_unauth(
    scope: LambdaUrlUnauthScope,
) -> EnumerationRun:
    """Crawl (optional) + probe every Lambda Function URL found."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope(
        Provider.AWS, "unauth-lambda-url", scope.max_concurrency, scope.timeout_s
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
    direct_hits: list[LambdaUrlHit] = []
    for raw in scope.urls:
        classified = classify_direct_url(raw)
        if classified is not None:
            direct_hits.append(classified)
    hits: dict[str, LambdaUrlHit] = {}
    for hit in (*crawl_hits, *direct_hits):
        hits.setdefault(hit.url, hit)
    targets = list(hits.values())

    identity = render_preamble(
        console,
        provider=Provider.AWS,
        service_label="unauth-lambda-url",
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
    reports: list[LambdaUrlProbeResult] = []
    errors = crawl_errors(scope.target_url, pages)

    if targets:
        sem = asyncio.Semaphore(scope.max_concurrency)

        async def _one(hit: LambdaUrlHit) -> LambdaUrlProbeResult:
            async with sem:
                return await probe(client, hit)

        async with httpx.AsyncClient(
            timeout=scope.timeout_s,
            headers={"User-Agent": scope.user_agent},
            follow_redirects=False,
        ) as client:
            reports = await asyncio.gather(*[_one(hit) for hit in targets])

    resources: list[dict[str, Any]] = []
    for report in reports:
        if report.error:
            continue
        resources.append(
            drop_empty(
                {
                    "kind": "lambda-url",
                    "id": report.url,
                    "url": report.url,
                    "function_hint": report.function_hint,
                    "region": report.region or "-",
                    "auth_mode": report.auth_mode,
                    "head_status": report.head_status or None,
                    "get_status": report.get_status or None,
                    "request_id": report.request_id or None,
                    "cors_wildcard": _tri(report.cors_wildcard),
                    "cors_credentials": _tri(report.cors_credentials),
                    "probes": ", ".join(report.probes) or None,
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

    cis_fields = {
        "target_url": scope.target_url or "(direct)",
        "urls_probed": len(reports),
        "public_urls": sum(1 for r in reports if r.auth_mode == "NONE"),
        "iam_urls": sum(1 for r in reports if r.auth_mode == "AWS_IAM"),
        "bundle_secrets": len(secret_findings),
    }

    service = ServiceResult(
        provider=Provider.AWS,
        service="unauth-lambda-url",
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
        finished_at=datetime.now(timezone.utc),
        duration_s=round((datetime.now(timezone.utc) - started).total_seconds(), 3),
    )

    render_service(console, service)
    _render_verdict(console, reports, secret_findings)
    render_summary(console, run)
    return run


def _render_verdict(
    console,
    reports: list[LambdaUrlProbeResult],
    crawl_secrets: list[dict[str, Any]],
) -> None:
    if not reports:
        console.print(
            Panel(
                "No Lambda Function URLs probed — supply --url.",
                title="verdict",
                border_style="warning",
            )
        )
        return
    public = [r for r in reports if r.auth_mode == "NONE"]
    iam = [r for r in reports if r.auth_mode == "AWS_IAM"]
    severity = "info"
    lines = [f"[success]{len(reports)}[/success] Lambda URL(s) probed."]
    if public:
        lines.append(
            f"[error]{len(public)}[/error] URL(s) respond publicly:"
            + "".join(f"\n  • {r.url}" for r in public)
        )
        severity = "error"
    if iam:
        lines.append(
            f"[success]{len(iam)}[/success] URL(s) require AWS_IAM signed invocation."
        )
    if crawl_secrets:
        lines.append(
            f"[error]{len(crawl_secrets)}[/error] credential match(es) in crawled bundles."
        )
        severity = "error"
    console.print(Panel("\n".join(lines), title="verdict", border_style=severity))


def _tri(value: bool | None) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "-"
