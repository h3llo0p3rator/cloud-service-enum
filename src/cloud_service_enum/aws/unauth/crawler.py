"""Back-compat shim — the crawler now lives under :mod:`core.unauth.crawler`.

Kept so existing AWS runners keep importing from the sibling package
without churn. Azure + GCP unauth modules import directly from
:mod:`cloud_service_enum.core.unauth.crawler`.
"""

from __future__ import annotations

from cloud_service_enum.core.unauth.crawler import (  # noqa: F401
    DEFAULT_USER_AGENT,
    MAX_BODY_BYTES,
    SKIP_EXTENSIONS,
    TEXTUAL_CONTENT_TYPES,
    CrawlScope,
    CrawlStats,
    FetchedPage,
    crawl,
)
