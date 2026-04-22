"""Back-compat shim — shared scaffolding now lives under :mod:`core.unauth`.

The functions in :mod:`core.unauth.common` are provider-parameterised,
so AWS runners pre-bind :data:`cloud_service_enum.core.models.Provider.AWS`
on the handful of helpers that need it (``build_identity`` /
``build_cse_scope`` / ``render_preamble``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cloud_service_enum.core.models import Provider, Scope
from cloud_service_enum.core.output import Console
from cloud_service_enum.core.unauth import common as _common
from cloud_service_enum.core.unauth.common import (  # noqa: F401  (re-exports)
    SHARED_CRAWL_DEFAULTS,
    crawl_errors,
    crawl_if_url,
    crawl_summary_row,
    drop_empty,
    scan_pages_for_secrets,
    scope_hosts,
)


def build_identity(label: str) -> dict[str, Any]:
    return _common.build_identity(Provider.AWS, label)


def build_cse_scope(service_label: str, max_concurrency: int, timeout_s: float) -> Scope:
    return _common.build_cse_scope(Provider.AWS, service_label, max_concurrency, timeout_s)


def render_preamble(
    console: Console,
    *,
    service_label: str,
    cse_scope: Scope,
    identity_label: str,
    extras: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return _common.render_preamble(
        console,
        provider=Provider.AWS,
        service_label=service_label,
        cse_scope=cse_scope,
        identity_label=identity_label,
        extras=extras,
    )
