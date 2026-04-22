"""Shared base class for every GCP service enumerator.

Most Google client libraries are synchronous; the base class wraps
``collect_project`` in :func:`asyncio.to_thread` to preserve the async
orchestration contract without requiring every service to be rewritten.
"""

from __future__ import annotations

import asyncio
import re
from abc import ABC, abstractmethod
from typing import Any

from cloud_service_enum.core.auth import CloudAuthenticator
from cloud_service_enum.core.concurrency import bounded_gather
from cloud_service_enum.core.models import Provider, Scope, ServiceResult
from cloud_service_enum.gcp.auth import GcpAuthenticator


class GcpService(ABC):
    """Base class shared by every GCP service enumerator."""

    service_name: str = ""
    is_regional = False

    async def enumerate(
        self, auth: CloudAuthenticator, scope: Scope
    ) -> ServiceResult:
        assert isinstance(auth, GcpAuthenticator)
        result = ServiceResult(provider=Provider.GCP, service=self.service_name)
        self._scope = scope  # exposed via :meth:`is_focused_on`
        projects = scope.project_ids or (
            [auth.config.project_id] if auth.config.project_id else []
        )
        if not projects:
            result.errors.append("no project_ids in scope and none on auth config")
            return result
        creds = await auth.credentials()

        async def _one(project_id: str) -> None:
            try:
                await asyncio.to_thread(self.collect_project, creds, project_id, result)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"[{project_id}] {format_gcp_error(exc)}")

        await bounded_gather(
            [_one(p) for p in projects if p], max_concurrency=scope.max_concurrency
        )
        return result

    def is_focused_on(self, service_name: str | None = None) -> bool:
        """True when the run should fetch deep-scan data for this service."""
        scope = getattr(self, "_scope", None)
        if scope is None:
            return False
        if scope.deep_scan:
            return True
        target = service_name or self.service_name
        return bool(scope.services) and target in scope.services

    @property
    def scope(self) -> Scope | None:
        """Scope from the current :meth:`enumerate` invocation, if any."""
        return getattr(self, "_scope", None)

    @abstractmethod
    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        """Synchronously populate ``result`` with resources for one project."""


def safe_list(iterable: Any) -> list[Any]:
    """Consume a possibly-exception-raising iterator into a list."""
    try:
        return list(iterable)
    except Exception:  # noqa: BLE001
        return []


_HTTP_ERROR_RE = re.compile(r"<HttpError\s+(\d+)\s+when requesting [^ ]+ returned \"([^\"]+)\"")


def format_gcp_error(exc: BaseException) -> str:
    """Render a GCP SDK exception as a short, human-friendly one-liner.

    ``googleapiclient.errors.HttpError`` and ``google.api_core.exceptions.*``
    both produce verbose multi-line messages with full request URLs and JSON
    detail blobs. The full payload is preserved in the JSON report; the
    terminal only needs the status + reason.
    """
    name = type(exc).__name__
    msg = str(exc)
    match = _HTTP_ERROR_RE.search(msg)
    if match:
        return f"{name}: {match.group(1)} {match.group(2)}"
    return f"{name}: {msg.splitlines()[0][:300]}"


def missing_sdk(result: ServiceResult, package: str) -> None:
    """Record a user-friendly error when an optional GCP SDK isn't installed.

    Each service defers its ``google-cloud-*`` import into ``collect_project``
    so that a single missing package only degrades that service instead of
    breaking the whole ``cse gcp enumerate`` CLI at import time.
    """
    result.errors.append(
        f"{package} is not installed; install the [gcp] extra "
        f"(pip install 'cloud-service-enum[gcp]')"
    )
