"""Authentication protocols shared by every provider."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict


class IdentitySummary(BaseModel):
    """Principal information returned after a credential check."""

    model_config = ConfigDict(extra="allow")

    provider: str
    principal: str
    display_name: str | None = None
    tenant_or_account: str | None = None
    auth_method: str | None = None
    roles: list[str] = []


@runtime_checkable
class CloudAuthenticator(Protocol):
    """Contract implemented by every provider's credential factory.

    Authenticators are expected to be instantiated once per run and
    reused by service enumerators. :meth:`test` MUST succeed (or raise
    :class:`~cloud_service_enum.core.errors.AuthenticationError`) before
    any service calls are made; :meth:`close` releases any underlying
    transports (aiohttp sessions, grpc channels, etc.).
    """

    provider: str

    async def test(self) -> IdentitySummary: ...

    async def close(self) -> None: ...
