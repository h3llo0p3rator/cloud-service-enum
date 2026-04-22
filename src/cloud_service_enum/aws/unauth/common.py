"""Shared scaffolding for ``cse aws unauth <service>`` runners.

Every unauth runner follows the same shape — optional crawl of an entry
URL, regex extraction on the returned bodies, a batch of probes against
public AWS endpoints, then an :class:`EnumerationRun` built on top of
the shared display helpers. This module holds the bits that don't vary
between services so each per-service runner stays short.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from cloud_service_enum.aws.unauth.crawler import (
    DEFAULT_USER_AGENT,
    CrawlScope,
    CrawlStats,
    FetchedPage,
    crawl,
)
from cloud_service_enum.core.display import render_config, render_identity
from cloud_service_enum.core.models import Provider, Scope
from cloud_service_enum.core.output import Console
from cloud_service_enum.core.secrets import scan_text

# Shared defaults for the crawler knobs every ``unauth`` command accepts.
# The CLI decorator in ``clis/aws_cli.py`` mirrors these so that behaviour
# stays aligned across ``cognito`` / ``s3`` / ``api-gateway``.
SHARED_CRAWL_DEFAULTS: dict[str, Any] = {
    "max_pages": 250,
    "max_concurrency": 10,
    "timeout_s": 15.0,
    "user_agent": DEFAULT_USER_AGENT,
}


def build_identity(label: str) -> dict[str, Any]:
    """Identity panel for a credential-less run."""
    return {
        "provider": Provider.AWS.value,
        "principal": "(unauthenticated)",
        "tenant_or_account": label,
        "auth_method": "none — public web crawl / probes",
    }


def build_cse_scope(service_label: str, max_concurrency: int, timeout_s: float) -> Scope:
    """Return the canonical ``Scope`` stamped on an unauth run."""
    return Scope(
        provider=Provider.AWS,
        services=[service_label],
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        iam_policy_bodies=False,
    )


def render_preamble(
    console: Console,
    *,
    service_label: str,
    cse_scope: Scope,
    identity_label: str,
    extras: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Render the identity + config panels every unauth runner prints."""
    identity = build_identity(identity_label)
    render_identity(console, identity)
    render_config(console, Provider.AWS, cse_scope, extras=extras or {})
    _ = service_label  # included on every ServiceResult; kept here for parity
    return identity


async def crawl_if_url(
    target_url: str | None,
    *,
    max_pages: int,
    max_concurrency: int,
    timeout_s: float,
    user_agent: str,
    extra_hosts: tuple[str, ...],
) -> tuple[list[FetchedPage], CrawlStats]:
    """Crawl ``target_url`` when set; return empties otherwise.

    Keeps the ``--url`` / direct-target duality a one-liner at call
    sites: ``pages, stats = await crawl_if_url(scope.target_url, …)``.
    """
    if not target_url:
        return [], CrawlStats()
    crawl_scope = CrawlScope(
        start_url=target_url,
        max_pages=max_pages,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        user_agent=user_agent,
        extra_hosts=extra_hosts,
    )
    return await crawl(crawl_scope)


def scan_pages_for_secrets(pages: list[FetchedPage]) -> list[dict[str, Any]]:
    """Run the shared credential regexes over every crawled text body."""
    findings: list[dict[str, Any]] = []
    for page in pages:
        if not page.body:
            continue
        for hit in scan_text(page.url, page.body):
            findings.append(hit.as_dict())
    return findings


def crawl_summary_row(
    target_url: str,
    stats: CrawlStats,
    pages: list[FetchedPage],
    *,
    extra: Mapping[str, Any] | None = None,
    secrets: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Build the ``crawl_summary`` resource row, or ``None`` when no crawl ran."""
    if not target_url:
        return None
    failed_pages = sum(1 for p in pages if p.error)
    row: dict[str, Any] = {
        "kind": "crawl_summary",
        "id": target_url,
        "name": urlparse(target_url).netloc or target_url,
        "pages_fetched": stats.pages_fetched,
        "js_files": stats.js_files,
        "kb_downloaded": round(stats.bytes_downloaded / 1024, 1),
        "hosts": ", ".join(sorted(stats.same_origin_hosts)),
        "failed_pages": failed_pages,
    }
    if secrets:
        row["secrets_found"] = secrets
    if extra:
        row.update(extra)
    return row


def scope_hosts(target_url: str | None, extra: tuple[str, ...]) -> list[str]:
    """Sorted, deduplicated list of hostnames counted as in-scope."""
    hosts: set[str] = set()
    if target_url:
        base = urlparse(target_url).netloc.lower()
        if base:
            hosts.add(base)
    for host in extra:
        cleaned = host.strip().lower()
        if cleaned:
            hosts.add(cleaned)
    return sorted(hosts)


def drop_empty(row: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose value is ``None`` or an empty string."""
    return {k: v for k, v in row.items() if v not in (None, "")}


def crawl_errors(target_url: str | None, pages: list[FetchedPage]) -> list[str]:
    """Surface the entry-URL fetch error if the crawl itself blew up."""
    if not target_url:
        return []
    for page in pages:
        if page.error and page.url == target_url:
            return [f"crawl: {page.url}: {page.error}"]
    return []
