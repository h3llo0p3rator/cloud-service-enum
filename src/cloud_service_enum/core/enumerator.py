"""Protocol every service enumerator implements."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from cloud_service_enum.core.auth import CloudAuthenticator
from cloud_service_enum.core.models import Scope, ServiceResult


@runtime_checkable
class ServiceEnumerator(Protocol):
    """Stateless enumerator bound to a single cloud service.

    Implementations are registered via
    :class:`cloud_service_enum.core.registry.ServiceRegistry` and
    instantiated once per run by the orchestrator.
    """

    service_name: str
    is_regional: bool

    async def enumerate(
        self, auth: CloudAuthenticator, scope: Scope
    ) -> ServiceResult: ...
