"""Elastic Beanstalk CNAME extraction + optional DNS resolution probes.

Beanstalk publishes public application URLs under
``<env-name>.<region>.elasticbeanstalk.com``; the CNAME points at an
environment-specific ELB such as ``awseb-…-<region>.elb.amazonaws.com``
(or the LB endpoint for ALB environments). Finding the CNAME in a
crawled bundle is attacker-useful because it pins an app to an AWS
region and an owning environment name; resolving the CNAME onwards is
optionally performed via asyncio's DNS resolver and flags whether the
target is still pointing at live EB infrastructure.

No HTTP calls are made against Beanstalk itself — the probe matrix is
limited to regex extraction plus DNS. The runner stays read-only.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from socket import AF_UNSPEC, SOCK_STREAM
from typing import Any
from urllib.parse import urlparse

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
)

# Capture both the legacy ``<env>.elasticbeanstalk.com`` and the newer
# regionalised ``<env>.<region>.elasticbeanstalk.com`` pattern.
_EB_HOSTNAME_RE = re.compile(
    r"\b([a-z0-9][a-z0-9\-]{0,61}[a-z0-9])"
    r"(?:\.([a-z0-9\-]+))?"
    r"\.elasticbeanstalk\.com\b",
    re.IGNORECASE,
)
_EB_LB_RE = re.compile(
    r"awseb-[\w\-]+\.[a-z0-9\-]+\.elb\.amazonaws\.com",
    re.IGNORECASE,
)
_ELB_SUFFIX = ".elb.amazonaws.com"


@dataclass(frozen=True)
class BeanstalkHit:
    """One ``*.elasticbeanstalk.com`` reference extracted from a crawl."""

    hostname: str
    environment: str
    region: str
    first_seen_url: str


@dataclass
class BeanstalkProbeReport:
    """Outcome of resolving a single Beanstalk hostname via DNS."""

    hostname: str
    environment: str
    region: str
    resolved: list[str] = field(default_factory=list)
    cname_target: str = ""
    is_eb_controlled: bool | None = None
    error: str = ""


def extract_hostnames(pages: list[FetchedPage]) -> list[BeanstalkHit]:
    """Return a de-duplicated list of Beanstalk host references."""
    seen: dict[str, BeanstalkHit] = {}
    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in _EB_HOSTNAME_RE.finditer(body):
            env = match.group(1).lower()
            region = (match.group(2) or "").lower()
            host = f"{env}.{region}.elasticbeanstalk.com" if region else f"{env}.elasticbeanstalk.com"
            seen.setdefault(
                host,
                BeanstalkHit(
                    hostname=host,
                    environment=env,
                    region=region,
                    first_seen_url=page.url,
                ),
            )
    return list(seen.values())


def classify_direct_hostname(raw: str) -> BeanstalkHit | None:
    """Turn an explicit ``--hostname`` into a :class:`BeanstalkHit`."""
    match = _EB_HOSTNAME_RE.fullmatch(raw.strip().lower())
    if not match:
        return None
    env = match.group(1).lower()
    region = (match.group(2) or "").lower()
    host = f"{env}.{region}.elasticbeanstalk.com" if region else f"{env}.elasticbeanstalk.com"
    return BeanstalkHit(
        hostname=host,
        environment=env,
        region=region,
        first_seen_url="(--hostname)",
    )


async def resolve(hit: BeanstalkHit, *, timeout_s: float) -> BeanstalkProbeReport:
    """Resolve a Beanstalk hostname and classify its CNAME target.

    We use :func:`asyncio.get_running_loop().getaddrinfo` because it
    doesn't require extra dependencies, but that only returns the final
    A records — to see the ``awseb-…`` CNAME we inspect ``canonname``.
    """
    report = BeanstalkProbeReport(
        hostname=hit.hostname,
        environment=hit.environment,
        region=hit.region,
    )
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(
                hit.hostname,
                None,
                family=AF_UNSPEC,
                type=SOCK_STREAM,
                flags=0x2,  # AI_CANONNAME
            ),
            timeout=timeout_s,
        )
    except (asyncio.TimeoutError, OSError) as exc:
        report.error = f"{exc.__class__.__name__}: {exc}"
        return report

    addresses: set[str] = set()
    canonical = ""
    for family, socktype, proto, canonname, sockaddr in infos:
        _ = (family, socktype, proto)
        if canonname and not canonical:
            canonical = canonname
        if isinstance(sockaddr, tuple) and sockaddr:
            addresses.add(str(sockaddr[0]))

    report.resolved = sorted(addresses)
    report.cname_target = canonical
    lowered = canonical.lower()
    report.is_eb_controlled = bool(
        _EB_LB_RE.search(lowered) or lowered.endswith(_ELB_SUFFIX)
    )
    return report


@dataclass
class BeanstalkUnauthScope:
    """Inputs for ``cse aws unauth beanstalk``."""

    target_url: str | None = None
    hostnames: tuple[str, ...] = ()
    max_pages: int = SHARED_CRAWL_DEFAULTS["max_pages"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()


async def run_beanstalk_unauth(
    scope: BeanstalkUnauthScope,
) -> EnumerationRun:
    """Crawl (optional) + resolve every Beanstalk hostname."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope(
        Provider.AWS, "unauth-beanstalk", scope.max_concurrency, scope.timeout_s
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
    direct_hits: list[BeanstalkHit] = []
    for raw in scope.hostnames:
        classified = classify_direct_hostname(raw)
        if classified is not None:
            direct_hits.append(classified)
    hits: dict[str, BeanstalkHit] = {}
    for hit in (*crawl_hits, *direct_hits):
        hits.setdefault(hit.hostname, hit)
    targets = list(hits.values())

    identity = render_preamble(
        console,
        provider=Provider.AWS,
        service_label="unauth-beanstalk",
        cse_scope=cse_scope,
        identity_label=identity_label or "(unknown)",
        extras={
            "Target URL": scope.target_url or "(none)",
            "Hostnames (direct)": ", ".join(scope.hostnames) or "(none)",
            "Targets": len(targets),
        },
    )

    svc_started = datetime.now(timezone.utc)
    reports: list[BeanstalkProbeReport] = []
    errors = crawl_errors(scope.target_url, pages)

    if targets:
        sem = asyncio.Semaphore(scope.max_concurrency)

        async def _one(hit: BeanstalkHit) -> BeanstalkProbeReport:
            async with sem:
                return await resolve(hit, timeout_s=scope.timeout_s)

        reports = await asyncio.gather(*[_one(hit) for hit in targets])

    resources: list[dict[str, Any]] = []
    for report in reports:
        if report.error and not report.resolved:
            # Suppress purely-failed lookups: DNS failure usually means
            # the environment was torn down. Still available in the run
            # totals via bruteforce_summary-style counters below.
            continue
        resources.append(
            drop_empty(
                {
                    "kind": "eb-env",
                    "id": report.hostname,
                    "name": report.environment,
                    "hostname": report.hostname,
                    "region": report.region or "-",
                    "cname_target": report.cname_target or "-",
                    "is_eb_controlled": _tri(report.is_eb_controlled),
                    "resolved_ips": ", ".join(report.resolved) or None,
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
        "hostnames_probed": len(reports),
        "hostnames_resolved": sum(1 for r in reports if r.resolved),
        "eb_controlled": sum(1 for r in reports if r.is_eb_controlled),
        "target_url": scope.target_url or "(direct)",
    }

    service = ServiceResult(
        provider=Provider.AWS,
        service="unauth-beanstalk",
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
    _render_verdict(console, scope, reports)
    render_summary(console, run)
    return run


def _render_verdict(
    console,
    scope: BeanstalkUnauthScope,
    reports: list[BeanstalkProbeReport],
) -> None:
    if not reports:
        console.print(
            Panel(
                "No Beanstalk hostnames probed — supply --url or --hostname.",
                title="verdict",
                border_style="warning",
            )
        )
        return
    live = [r for r in reports if r.resolved]
    eb = [r for r in reports if r.is_eb_controlled]
    severity = "info"
    lines = [
        f"[success]{len(live)}[/success] of {len(reports)} Beanstalk "
        "hostname(s) resolved."
    ]
    if eb:
        lines.append(
            f"[success]{len(eb)}[/success] hostname(s) still point at "
            "live EB load balancers."
        )
    console.print(Panel("\n".join(lines), title="verdict", border_style=severity))
    _ = scope


def _tri(value: bool | None) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "-"
