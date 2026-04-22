"""Cloud-agnostic scaffolding for ``cse <provider> unauth <service>`` runs."""

from __future__ import annotations

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
from cloud_service_enum.core.unauth.crawler import (
    DEFAULT_USER_AGENT,
    MAX_BODY_BYTES,
    CrawlScope,
    CrawlStats,
    FetchedPage,
    crawl,
)

__all__ = [
    "CrawlScope",
    "CrawlStats",
    "DEFAULT_USER_AGENT",
    "FetchedPage",
    "MAX_BODY_BYTES",
    "SHARED_CRAWL_DEFAULTS",
    "build_cse_scope",
    "build_identity",
    "crawl",
    "crawl_errors",
    "crawl_if_url",
    "crawl_summary_row",
    "drop_empty",
    "render_preamble",
    "scan_pages_for_secrets",
    "scope_hosts",
]
