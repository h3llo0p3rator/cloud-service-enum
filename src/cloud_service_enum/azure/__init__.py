"""Async Azure enumerator package (registers services on import)."""

from __future__ import annotations

from cloud_service_enum.azure.auth import AzureAuthenticator

from cloud_service_enum.azure import services as _services  # noqa: F401

__all__ = ["AzureAuthenticator"]
