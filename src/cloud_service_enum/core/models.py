"""Pydantic data models for enumeration results.

The shape is deliberately flat: every service returns a
:class:`ServiceResult` containing an opaque list of resources plus
structured metadata. Consumers (reporters, formatters, tests) only need
to understand these models to work with any provider.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Provider(StrEnum):
    """Cloud provider identifier."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OSINT = "osint"


class Severity(StrEnum):
    """Severity level attached to findings and log entries."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResourceRef(BaseModel):
    """Lightweight reference to a cloud resource."""

    model_config = ConfigDict(frozen=True)

    kind: str
    id: str
    name: str | None = None
    region: str | None = None
    arn: str | None = None


class Scope(BaseModel):
    """Input parameters that constrain a single enumeration run."""

    model_config = ConfigDict(extra="allow")

    provider: Provider
    regions: list[str] = Field(default_factory=list)
    subscription_ids: list[str] = Field(default_factory=list)
    project_ids: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    max_concurrency: int = 10
    timeout_s: float = 120.0
    # Deep-scan toggles. ``deep_scan`` forces every service to run its
    # medium-cost "deep" branch regardless of ``services`` scoping; the
    # normal pattern is to leave this False and let each service opt in
    # via :meth:`ServiceContext.is_focused_on`. ``secret_scan`` enables
    # regex credential detection on every text surface a deep branch
    # fetches (env-var maps, startup scripts, workflow definitions, etc.).
    deep_scan: bool = False
    secret_scan: bool = False
    iam_policy_bodies: bool = True
    s3_secret_scan: bool = False
    s3_scan_file_limit: int = 100
    s3_scan_size_limit_kb: int = 500


class ServiceResult(BaseModel):
    """Outcome of enumerating a single service.

    ``resources`` is free-form so individual services can attach
    whichever fields they collected; ``cis_fields`` highlights the
    subset relevant for CIS benchmark evaluation without duplicating
    data, and ``errors`` captures non-fatal issues encountered during
    the run.
    """

    model_config = ConfigDict(extra="allow")

    provider: Provider
    service: str
    resources: list[dict[str, Any]] = Field(default_factory=list)
    cis_fields: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def count(self) -> int:
        return len(self.resources)


class EnumerationRun(BaseModel):
    """Top-level document representing an entire enumeration session."""

    model_config = ConfigDict(extra="allow")

    provider: Provider
    scope: Scope
    identity: dict[str, Any] = Field(default_factory=dict)
    services: list[ServiceResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    duration_s: float = 0.0

    def by_service(self) -> dict[str, ServiceResult]:
        return {s.service: s for s in self.services}

    def resource_total(self) -> int:
        return sum(s.count for s in self.services)

    def error_total(self) -> int:
        return sum(len(s.errors) for s in self.services)
