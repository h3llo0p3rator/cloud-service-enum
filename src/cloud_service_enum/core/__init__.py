"""Core contracts and utilities shared by every cloud provider module."""

from __future__ import annotations

from cloud_service_enum.core.auth import CloudAuthenticator, IdentitySummary
from cloud_service_enum.core.concurrency import bounded_gather, run_services
from cloud_service_enum.core.config import Settings, get_settings
from cloud_service_enum.core.enumerator import ServiceEnumerator
from cloud_service_enum.core.errors import (
    AuthenticationError,
    CloudServiceError,
    EnumerationError,
    PermissionError as CseePermissionError,
    RateLimited,
)
from cloud_service_enum.core.models import (
    EnumerationRun,
    Provider,
    ResourceRef,
    Scope,
    ServiceResult,
    Severity,
)
from cloud_service_enum.core.output import Console, get_console, progress_bar
from cloud_service_enum.core.registry import ServiceRegistry, registry
from cloud_service_enum.core.runner import run_provider

__all__ = [
    "AuthenticationError",
    "CloudAuthenticator",
    "CloudServiceError",
    "Console",
    "CseePermissionError",
    "EnumerationError",
    "EnumerationRun",
    "IdentitySummary",
    "Provider",
    "RateLimited",
    "ResourceRef",
    "Scope",
    "ServiceEnumerator",
    "ServiceRegistry",
    "ServiceResult",
    "Settings",
    "Severity",
    "bounded_gather",
    "get_console",
    "get_settings",
    "progress_bar",
    "registry",
    "run_provider",
    "run_services",
]
