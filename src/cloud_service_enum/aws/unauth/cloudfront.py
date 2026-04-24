"""CloudFront Host-header / Origin override probes against a target URL.

Given a single target, this module issues three HTTP requests:

1. A baseline ``GET /`` (so we have a stable reference).
2. The same request with ``Host: <alt>`` — this is the classic
   "CloudFront cache key confusion" check: a distribution configured to
   forward the Host header to its origin will happily respond to any
   hostname that resolves to the distribution's IP, letting an attacker
   pivot to alternate alt-domain exposures.
3. The same request with ``Origin: https://evil.example`` — lets us
   observe overly-permissive ``Access-Control-Allow-Origin`` echoing.

Every response is read with a ``max_size`` cap and only read-only calls
are made. The classifier compares headers + body size against the
baseline and flags meaningful divergence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from rich.panel import Panel

from cloud_service_enum.aws.unauth.crawler import DEFAULT_USER_AGENT
from cloud_service_enum.core.display import render_service, render_summary
from cloud_service_enum.core.models import EnumerationRun, Provider, ServiceResult
from cloud_service_enum.core.output import get_console
from cloud_service_enum.core.unauth.common import (
    SHARED_CRAWL_DEFAULTS,
    build_cse_scope,
    drop_empty,
    render_preamble,
)

_BASELINE_UA = "cloud-service-enum/2.0 (+unauth cloudfront)"


@dataclass
class CloudFrontProbeResult:
    """One probe slot against the target URL."""

    probe: str
    status: int = 0
    body_size: int = 0
    cache_header: str = ""
    x_amz_cf_id: str = ""
    x_amz_cf_pop: str = ""
    via_header: str = ""
    allow_origin: str = ""
    diff_vs_baseline: str = ""
    error: str = ""


@dataclass
class CloudFrontReport:
    """Aggregate of every probe slot for a single target."""

    target: str
    host_override: str
    probes: list[CloudFrontProbeResult] = field(default_factory=list)


async def probe_cloudfront(
    client: httpx.AsyncClient,
    target_url: str,
    *,
    host_override: str | None = None,
    origin_override: str = "https://evil.example",
) -> CloudFrontReport:
    """Run the three-way probe matrix against ``target_url``."""
    baseline = await _one_probe(client, target_url, name="baseline", headers={})
    report = CloudFrontReport(
        target=target_url,
        host_override=host_override or "",
        probes=[baseline],
    )
    if host_override:
        host_probe = await _one_probe(
            client,
            target_url,
            name="host-override",
            headers={"Host": host_override},
        )
        host_probe.diff_vs_baseline = _summarise_diff(baseline, host_probe)
        report.probes.append(host_probe)
    origin_probe = await _one_probe(
        client,
        target_url,
        name="origin-override",
        headers={"Origin": origin_override},
    )
    origin_probe.diff_vs_baseline = _summarise_diff(baseline, origin_probe)
    report.probes.append(origin_probe)
    return report


async def _one_probe(
    client: httpx.AsyncClient,
    url: str,
    *,
    name: str,
    headers: dict[str, str],
) -> CloudFrontProbeResult:
    merged = {"User-Agent": _BASELINE_UA, **headers}
    result = CloudFrontProbeResult(probe=name)
    try:
        resp = await client.get(url, headers=merged, follow_redirects=False)
    except httpx.HTTPError as exc:
        result.error = f"{exc.__class__.__name__}: {exc}"
        return result
    body = resp.content or b""
    result.status = resp.status_code
    result.body_size = len(body)
    result.cache_header = (resp.headers.get("x-cache") or "").strip()
    result.x_amz_cf_id = (resp.headers.get("x-amz-cf-id") or "").strip()
    result.x_amz_cf_pop = (resp.headers.get("x-amz-cf-pop") or "").strip()
    result.via_header = (resp.headers.get("via") or "").strip()
    result.allow_origin = (
        resp.headers.get("access-control-allow-origin") or ""
    ).strip()
    return result


def _summarise_diff(
    baseline: CloudFrontProbeResult, probe: CloudFrontProbeResult
) -> str:
    """Short free-form string describing divergence from the baseline."""
    if probe.error:
        return f"error: {probe.error}"
    notes: list[str] = []
    if probe.status != baseline.status:
        notes.append(f"status {baseline.status} → {probe.status}")
    size_delta = probe.body_size - baseline.body_size
    if abs(size_delta) > max(64, baseline.body_size * 0.1):
        notes.append(f"body size Δ {size_delta:+d} bytes")
    if probe.cache_header and probe.cache_header != baseline.cache_header:
        notes.append(f"x-cache: {probe.cache_header}")
    if probe.allow_origin and probe.allow_origin != baseline.allow_origin:
        notes.append(f"ACAO: {probe.allow_origin}")
    return " · ".join(notes) if notes else "no significant diff"


def is_cloudfront_response(report: CloudFrontReport) -> bool:
    """Heuristic: does anything about the response fingerprint CloudFront?"""
    for probe in report.probes:
        if probe.x_amz_cf_id or probe.x_amz_cf_pop:
            return True
        if "cloudfront" in probe.via_header.lower():
            return True
    return False


@dataclass
class CloudFrontUnauthScope:
    """Inputs for ``cse aws unauth cloudfront``."""

    target_url: str
    host_override: str | None = None
    origin_override: str = "https://evil.example"
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    user_agent: str = DEFAULT_USER_AGENT


async def run_cloudfront_unauth(
    scope: CloudFrontUnauthScope,
) -> EnumerationRun:
    """Probe a single URL for CloudFront Host / Origin override behaviour."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope(
        Provider.AWS, "unauth-cloudfront", scope.max_concurrency, scope.timeout_s
    )
    identity_label = urlparse(scope.target_url).netloc or scope.target_url
    identity = render_preamble(
        console,
        provider=Provider.AWS,
        service_label="unauth-cloudfront",
        cse_scope=cse_scope,
        identity_label=identity_label,
        extras={
            "Target URL": scope.target_url,
            "Host override": scope.host_override or "(auto)",
            "Origin override": scope.origin_override,
        },
    )

    svc_started = datetime.now(timezone.utc)
    async with httpx.AsyncClient(
        timeout=scope.timeout_s,
        headers={"User-Agent": scope.user_agent},
        follow_redirects=False,
    ) as client:
        report = await probe_cloudfront(
            client,
            scope.target_url,
            host_override=scope.host_override,
            origin_override=scope.origin_override,
        )

    resources: list[dict[str, Any]] = []
    for probe_result in report.probes:
        resources.append(
            drop_empty(
                {
                    "kind": "cf-response",
                    "id": f"{scope.target_url}#{probe_result.probe}",
                    "probe": probe_result.probe,
                    "status": probe_result.status or None,
                    "body_size": probe_result.body_size or None,
                    "cache_header": probe_result.cache_header or None,
                    "x_amz_cf_id": probe_result.x_amz_cf_id or None,
                    "x_amz_cf_pop": probe_result.x_amz_cf_pop or None,
                    "via_header": probe_result.via_header or None,
                    "allow_origin": probe_result.allow_origin or None,
                    "diff_vs_baseline": probe_result.diff_vs_baseline or None,
                    "error": probe_result.error or None,
                }
            )
        )

    cis_fields = {
        "target": scope.target_url,
        "host_override": report.host_override or "(auto)",
        "is_cloudfront": "yes" if is_cloudfront_response(report) else "no",
        "probes_run": len(report.probes),
    }
    errors = [
        f"{p.probe}: {p.error}"
        for p in report.probes
        if p.error
    ]

    service = ServiceResult(
        provider=Provider.AWS,
        service="unauth-cloudfront",
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
    _render_verdict(console, report)
    render_summary(console, run)
    return run


def _render_verdict(console, report: CloudFrontReport) -> None:
    is_cf = is_cloudfront_response(report)
    diffs = [p for p in report.probes if p.diff_vs_baseline]
    severity = "info"
    lines: list[str] = []
    if is_cf:
        lines.append("[success]CloudFront edge detected[/success] (x-amz-cf-id present).")
    else:
        lines.append("[warning]No CloudFront fingerprint[/warning] — probe inconclusive.")
    if diffs:
        lines.append(
            f"[error]{len(diffs)}[/error] override probe(s) diverged from "
            "baseline:"
            + "".join(
                f"\n  • {p.probe}: {p.diff_vs_baseline}" for p in diffs
            )
        )
        severity = "warning"
    console.print(Panel("\n".join(lines), title="verdict", border_style=severity))
