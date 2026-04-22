"""Orchestrates ``cse gcp unauth bucket``.

Mirrors the AWS S3 runner: optional crawl → regex extraction + direct
targets + bruteforce → per-bucket metadata/list/IAM/website probes →
object sampling → one :class:`EnumerationRun` rendered by the shared
Rich helpers and piped through the standard report writers.
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
from cloud_service_enum.gcp.unauth.bucket import (
    BucketHit,
    BucketProbeReport,
    bruteforce_names,
    extract_buckets,
    load_default_suffix_wordlist,
    probe_bucket,
    scan_public_objects,
)


@dataclass
class BucketUnauthScope:
    """Inputs for ``cse gcp unauth bucket``."""

    target_url: str | None = None
    buckets: tuple[str, ...] = ()
    bruteforce: bool = False
    bruteforce_prefixes: tuple[str, ...] = ()
    bruteforce_wordlist: Path | None = None
    max_objects: int = 100
    max_object_size_kb: int = 500
    max_pages: int = SHARED_CRAWL_DEFAULTS["max_pages"]
    max_concurrency: int = SHARED_CRAWL_DEFAULTS["max_concurrency"]
    timeout_s: float = SHARED_CRAWL_DEFAULTS["timeout_s"]
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()


async def run_bucket_unauth(scope: BucketUnauthScope) -> EnumerationRun:
    """Crawl (optional) + probe every discovered / supplied GCS bucket."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = build_cse_scope(
        Provider.GCP, "unauth-bucket", scope.max_concurrency, scope.timeout_s
    )
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

    bruteforce_candidates = _build_bruteforce_candidates(scope)
    targets = _merge_targets(crawl_hits, scope.buckets, bruteforce_candidates)

    render_preamble(
        console,
        provider=Provider.GCP,
        service_label="unauth-bucket",
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
            "In-scope hosts": ", ".join(scope_hosts(scope.target_url, scope.extra_hosts))
            or "(none)",
        },
    )

    svc_started = datetime.now(timezone.utc)
    reports: list[BucketProbeReport] = []
    sampled_objects: list[dict[str, Any]] = []
    bucket_secrets: list[dict[str, Any]] = []
    errors = crawl_errors(scope.target_url, pages)

    if targets:
        sem = asyncio.Semaphore(scope.max_concurrency)
        async with httpx.AsyncClient(
            timeout=scope.timeout_s,
            headers={"User-Agent": scope.user_agent},
            follow_redirects=False,
        ) as client:
            reports = await asyncio.gather(
                *[_probe_with_sem(client, sem, hit) for hit in targets]
            )
            for report in reports:
                if not report.public_list or not report.object_names:
                    continue
                sampled, report_secrets = await scan_public_objects(
                    client,
                    report.bucket,
                    report.object_names,
                    max_objects=scope.max_objects,
                    max_object_size_kb=scope.max_object_size_kb,
                )
                sampled_objects.extend(sampled)
                bucket_secrets.extend(report_secrets)

    resources = _build_resources(
        scope,
        targets,
        reports,
        sampled_objects,
        bucket_secrets,
        pages,
        stats,
        secret_findings,
        bruteforce_candidates,
    )
    cis_fields = _summarise(
        scope,
        targets,
        reports,
        sampled_objects,
        bucket_secrets,
        secret_findings,
        bruteforce_candidates,
    )

    service = _finalise_service(
        "unauth-bucket", svc_started, resources, cis_fields, errors
    )
    identity = build_identity(Provider.GCP, identity_label or "(unknown)")
    run = _finalise_run(started, cse_scope, identity, service)

    render_service(console, service)
    _render_verdict(console, scope, reports, bucket_secrets, secret_findings)
    render_summary(console, run)
    return run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _probe_with_sem(
    client: httpx.AsyncClient, sem: asyncio.Semaphore, hit: BucketHit
) -> BucketProbeReport:
    async with sem:
        return await probe_bucket(client, hit)


def _build_bruteforce_candidates(scope: BucketUnauthScope) -> list[str]:
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
    return list(bruteforce_names(scope.bruteforce_prefixes, suffixes))


def _merge_targets(
    crawl_hits: list[BucketHit],
    direct: tuple[str, ...],
    bruteforce_candidates: list[str],
) -> list[BucketHit]:
    seen: dict[str, BucketHit] = {}
    for hit in crawl_hits:
        seen.setdefault(hit.name, hit)
    for name in direct:
        cleaned = name.strip().lower()
        if cleaned and cleaned not in seen:
            seen[cleaned] = BucketHit(name=cleaned, first_seen_url="(--bucket)")
    for name in bruteforce_candidates:
        cleaned = name.strip().lower()
        if cleaned and cleaned not in seen:
            seen[cleaned] = BucketHit(name=cleaned, first_seen_url="(bruteforce)")
    return list(seen.values())


def _build_resources(
    scope: BucketUnauthScope,
    targets: list[BucketHit],
    reports: list[BucketProbeReport],
    sampled_objects: list[dict[str, Any]],
    bucket_secrets: list[dict[str, Any]],
    pages: list[FetchedPage],
    stats: Any,
    crawl_secrets: list[dict[str, Any]],
    bruteforce_candidates: list[str],
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for report in reports:
        # Only surface confirmed-existing buckets. Everything else is
        # DNS / TLS / auth noise that crowds out the actionable rows.
        if report.existence != "exists":
            continue
        matching = [f for f in bucket_secrets if f.get("bucket") == report.bucket]
        resources.append(
            drop_empty(
                {
                    "kind": "gcs_bucket",
                    "id": report.bucket,
                    "name": report.bucket,
                    "project_number": report.project_number or None,
                    "location": report.location or None,
                    "storage_class": report.storage_class or None,
                    "uniform_access": _tri(report.uniform_access),
                    "public_list": _tri(report.public_list),
                    "public_iam": _tri(report.public_iam),
                    "website": _tri(report.website),
                    "website_main_page": report.website_main_page or None,
                    "cors_wildcard": _tri(report.cors_wildcard),
                    "cors_credentials": _tri(report.cors_credentials),
                    "objects_sampled": len(
                        [o for o in sampled_objects if o.get("bucket") == report.bucket]
                    ) or None,
                    "first_seen_url": _first_seen(targets, report.bucket),
                    "probes": report.summary,
                    "iam_bindings": report.iam_bindings or None,
                    "secrets_found": matching or None,
                }
            )
        )

    for obj in sampled_objects:
        resources.append(
            drop_empty(
                {
                    "kind": "gcs_object",
                    "id": f"{obj['bucket']}/{obj['key']}",
                    "name": obj["key"],
                    "bucket": obj["bucket"],
                    "size": obj.get("size"),
                    "bytes_scanned": obj.get("bytes_scanned"),
                    "secret_count": obj.get("secret_count") or None,
                }
            )
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


def _summarise(
    scope: BucketUnauthScope,
    targets: list[BucketHit],
    reports: list[BucketProbeReport],
    sampled_objects: list[dict[str, Any]],
    bucket_secrets: list[dict[str, Any]],
    crawl_secrets: list[dict[str, Any]],
    bruteforce_candidates: list[str],
) -> dict[str, Any]:
    existing = [r for r in reports if r.existence == "exists"]
    return {
        "target_url": scope.target_url or "(direct)",
        "buckets_probed": len(targets),
        "buckets_existing": len(existing),
        "public_list_buckets": sum(1 for r in reports if r.public_list),
        "public_iam_buckets": sum(1 for r in reports if r.public_iam),
        "website_buckets": sum(1 for r in reports if r.website),
        "projects_attributed": sum(1 for r in existing if r.project_number),
        "objects_sampled": len(sampled_objects),
        "bucket_object_secrets": len(bucket_secrets),
        "bundle_secrets": len(crawl_secrets),
        "bruteforce_candidates": len(bruteforce_candidates),
    }


def _render_verdict(
    console,
    scope: BucketUnauthScope,
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

    existing = [r for r in reports if r.existence == "exists"]
    public_list = [r for r in reports if r.public_list]
    public_iam = [r for r in reports if r.public_iam]
    severity = "info"
    lines: list[str] = [
        f"[success]{len(existing)}[/success] of {len(reports)} probed bucket(s) exist."
    ]
    attributed = [r for r in existing if r.project_number]
    if attributed:
        lines.append(
            f"[success]{len(attributed)}[/success] bucket(s) leak owning projectNumber:"
            + "".join(f"\n  • {r.bucket} → project {r.project_number}" for r in attributed)
        )
    if public_list:
        lines.append(
            f"[error]{len(public_list)}[/error] bucket(s) allow unauthenticated listing:"
            + "".join(f"\n  • {r.bucket}" for r in public_list)
        )
        severity = "error"
    if public_iam:
        lines.append(
            f"[error]{len(public_iam)}[/error] bucket(s) grant allUsers / "
            "allAuthenticatedUsers in their IAM policy."
        )
        severity = "error"
    if bucket_secrets:
        lines.append(
            f"[error]{len(bucket_secrets)}[/error] credential match(es) "
            "inside public object bodies."
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


def _first_seen(targets: list[BucketHit], bucket: str) -> str:
    for hit in targets:
        if hit.name == bucket:
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
        provider=Provider.GCP,
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
        provider=Provider.GCP,
        scope=cse_scope,
        identity=identity,
        services=[service],
        started_at=started,
        finished_at=finished,
        duration_s=round((finished - started).total_seconds(), 3),
    )
