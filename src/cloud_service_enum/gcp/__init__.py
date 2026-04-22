"""Async-style GCP enumerator package (registers services on import)."""

from __future__ import annotations

from cloud_service_enum.gcp.auth import GcpAuthenticator

from cloud_service_enum.gcp import services as _services  # noqa: F401

__all__ = ["GcpAuthenticator"]
