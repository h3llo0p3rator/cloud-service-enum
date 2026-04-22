"""Exception hierarchy for cloud enumeration.

Every error raised by the package inherits from :class:`CloudServiceError`
so callers can catch the entire family with a single ``except`` clause.
"""

from __future__ import annotations


class CloudServiceError(Exception):
    """Base class for all cloud-service-enum errors."""


class AuthenticationError(CloudServiceError):
    """Raised when credentials cannot be obtained or validated."""


class PermissionError(CloudServiceError):
    """Raised when a caller lacks permission for a specific API call.

    Distinct from :class:`builtins.PermissionError`; exported as
    ``CseePermissionError`` at package top level to avoid shadowing.
    """


class RateLimited(CloudServiceError):
    """Raised when the cloud provider throttles the client."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class EnumerationError(CloudServiceError):
    """Generic failure enumerating a single service."""

    def __init__(self, service: str, message: str) -> None:
        super().__init__(f"{service}: {message}")
        self.service = service
