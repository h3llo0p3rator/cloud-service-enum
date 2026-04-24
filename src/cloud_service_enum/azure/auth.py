"""Async Azure authenticator covering every supported credential type."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from azure.core.credentials import AccessToken
from azure.core.credentials_async import AsyncTokenCredential
from azure.identity.aio import (
    AzureCliCredential,
    CertificateCredential,
    ClientSecretCredential,
    DefaultAzureCredential,
    ManagedIdentityCredential,
    WorkloadIdentityCredential,
)

from cloud_service_enum.core.auth import CloudAuthenticator, IdentitySummary
from cloud_service_enum.core.errors import AuthenticationError

_logger = logging.getLogger(__name__)

BearerResource = Literal["management", "graph", "vault", "devops", "arm"]

_BEARER_RESOURCE_SCOPES: dict[str, str] = {
    "management": "https://management.azure.com/.default",
    "arm": "https://management.azure.com/.default",
    "graph": "https://graph.microsoft.com/.default",
    "vault": "https://vault.azure.net/.default",
    # Azure DevOps SPN app id
    "devops": "499b84ac-1321-427f-aa17-267ca6975798/.default",
}


class _SharedCredential(AsyncTokenCredential):
    """Non-closing proxy around an ``AsyncTokenCredential``.

    Azure management clients close the credential they are given when they
    exit their ``async with`` block. We share one credential across many
    concurrently-running services, so we hand each client this proxy; the
    real credential is closed once, explicitly, by
    :meth:`AzureAuthenticator.close`.
    """

    __slots__ = ("_inner",)

    def __init__(self, inner: AsyncTokenCredential) -> None:
        self._inner = inner

    async def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        return await self._inner.get_token(*scopes, **kwargs)

    async def close(self) -> None:  # noqa: D401 - intentionally a no-op
        return None

    async def __aenter__(self) -> _SharedCredential:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None


def _expiry_from_jwt(token: str) -> int:
    """Return the ``exp`` claim from a JWT, or ``now + 60 min`` if missing.

    Bearer tokens supplied via ``--bearer-token`` are not validated — we
    simply peek at the unsigned payload to learn when they'll stop
    working so token-refresh loops in the SDK do not thrash.
    """
    fallback = int(time.time()) + 3600
    parts = token.split(".")
    if len(parts) < 2:
        return fallback
    try:
        payload = parts[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError, json.JSONDecodeError):
        _logger.warning(
            "Could not decode bearer token payload; assuming 60 minute lifetime."
        )
        return fallback
    exp = claims.get("exp")
    if isinstance(exp, int):
        return exp
    _logger.warning(
        "Bearer token has no 'exp' claim; assuming 60 minute lifetime."
    )
    return fallback


class _StaticBearerCredential(AsyncTokenCredential):
    """Return a pre-issued bearer token regardless of requested scope.

    The token is intended to be replayed against a single resource (the
    one encoded in its ``aud`` claim). Callers pick which resource the
    token is aimed at via ``AzureAuthConfig.bearer_resource`` — services
    that need a different scope will simply fail to acquire a token and
    surface the error in their result.
    """

    __slots__ = ("_token",)

    def __init__(self, token: str, expires_on: int | None = None) -> None:
        self._token = AccessToken(token, expires_on or _expiry_from_jwt(token))

    async def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        _ = scopes, kwargs
        return self._token

    async def close(self) -> None:
        return None

    async def __aenter__(self) -> _StaticBearerCredential:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None


class _AsyncUsernamePasswordCredential(AsyncTokenCredential):
    """Async adapter around the sync ``UsernamePasswordCredential``.

    ``azure-identity`` deliberately omits ``UsernamePasswordCredential`` from
    its ``aio`` module because the ROPC flow is discouraged. We still want to
    support it for legacy tenants, so we run the sync credential on a worker
    thread to satisfy the async contract.
    """

    def __init__(
        self,
        *,
        client_id: str,
        username: str,
        password: str,
        tenant_id: str,
    ) -> None:
        from azure.identity import UsernamePasswordCredential as _SyncUPC

        self._sync = _SyncUPC(
            client_id=client_id,
            username=username,
            password=password,
            tenant_id=tenant_id,
        )

    async def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        return await asyncio.to_thread(self._sync.get_token, *scopes, **kwargs)

    async def close(self) -> None:
        await asyncio.to_thread(self._sync.close)

    async def __aenter__(self) -> _AsyncUsernamePasswordCredential:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()


@dataclass
class AzureAuthConfig:
    """Inputs describing how to build an Azure credential.

    Supported auth methods, in order of precedence:
    - pre-issued bearer token (``bearer_token``)
    - service principal with secret (``tenant_id`` + ``client_id`` + ``client_secret``)
    - service principal with certificate (``tenant_id`` + ``client_id`` + ``certificate_path``)
    - username + password (``tenant_id`` + ``client_id`` + ``username`` + ``password``)
    - workload identity federation (``tenant_id`` + ``client_id`` + ``federated_token_file``)
    - managed identity (``use_managed_identity`` true, optional ``client_id``)
    - Azure CLI (``use_cli`` true)
    - default chain (none of the above)
    """

    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    certificate_path: str | None = None
    certificate_password: str | None = None
    username: str | None = None
    password: str | None = None
    federated_token_file: str | None = None
    use_managed_identity: bool = False
    use_cli: bool = False
    subscription_id: str | None = None
    bearer_token: str | None = None
    bearer_resource: BearerResource = "management"
    bearer_expires_on: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def method(self) -> str:
        if self.bearer_token:
            return "bearer-token"
        if self.client_secret:
            return "client-secret"
        if self.certificate_path:
            return "client-certificate"
        if self.password:
            return "username-password"
        if self.federated_token_file:
            return "workload-identity-federation"
        if self.use_managed_identity:
            return "managed-identity"
        if self.use_cli:
            return "azure-cli"
        return "default-chain"

    @property
    def bearer_scope(self) -> str:
        """Resolve ``bearer_resource`` to the full OAuth scope URI."""
        return _BEARER_RESOURCE_SCOPES.get(
            self.bearer_resource, _BEARER_RESOURCE_SCOPES["management"]
        )


class AzureAuthenticator(CloudAuthenticator):
    """Builds and caches an async Azure credential."""

    provider = "azure"

    def __init__(self, config: AzureAuthConfig | None = None) -> None:
        self.config = config or AzureAuthConfig()
        self._credential: AsyncTokenCredential | None = None
        self._shared: _SharedCredential | None = None

    def _build(self) -> AsyncTokenCredential:
        cfg = self.config
        if cfg.bearer_token:
            return _StaticBearerCredential(
                cfg.bearer_token, expires_on=cfg.bearer_expires_on
            )
        if cfg.client_secret and cfg.tenant_id and cfg.client_id:
            return ClientSecretCredential(
                tenant_id=cfg.tenant_id,
                client_id=cfg.client_id,
                client_secret=cfg.client_secret,
            )
        if cfg.certificate_path and cfg.tenant_id and cfg.client_id:
            return CertificateCredential(
                tenant_id=cfg.tenant_id,
                client_id=cfg.client_id,
                certificate_path=cfg.certificate_path,
                password=cfg.certificate_password,
            )
        if cfg.password and cfg.username and cfg.tenant_id and cfg.client_id:
            return _AsyncUsernamePasswordCredential(
                client_id=cfg.client_id,
                username=cfg.username,
                password=cfg.password,
                tenant_id=cfg.tenant_id,
            )
        if cfg.federated_token_file and cfg.tenant_id and cfg.client_id:
            return WorkloadIdentityCredential(
                tenant_id=cfg.tenant_id,
                client_id=cfg.client_id,
                token_file_path=cfg.federated_token_file,
            )
        if cfg.use_managed_identity:
            return ManagedIdentityCredential(client_id=cfg.client_id)
        if cfg.use_cli:
            return AzureCliCredential()
        return DefaultAzureCredential()

    def credential(self) -> AsyncTokenCredential:
        """Return a credential safe to pass into any number of async clients.

        The returned object is a non-closing proxy: management clients that
        call ``close()`` on it during their ``__aexit__`` do not affect other
        clients sharing the same underlying credential.
        """
        if self._credential is None:
            self._credential = self._build()
        if self._shared is None:
            self._shared = _SharedCredential(self._credential)
        return self._shared

    async def test(self) -> IdentitySummary:
        cred = self.credential()
        scope = (
            self.config.bearer_scope
            if self.config.bearer_token
            else "https://management.azure.com/.default"
        )
        try:
            token = await cred.get_token(scope)
        except Exception as exc:
            raise AuthenticationError(f"failed to acquire Azure token: {exc}") from exc
        principal = (
            self.config.client_id
            or self.config.username
            or ("bearer-token" if self.config.bearer_token else "default-identity")
        )
        return IdentitySummary(
            provider="azure",
            principal=principal,
            display_name=self.config.username,
            tenant_or_account=self.config.tenant_id,
            auth_method=self.config.method,
            expires_on=token.expires_on,
        )

    async def close(self) -> None:
        if self._credential is not None:
            await self._credential.close()
            self._credential = None
        self._shared = None

    async def discover_subscriptions(self) -> list[str]:
        """List enabled subscription ids visible to the credential.

        Used by :func:`run_provider` to auto-populate
        ``scope.subscription_ids`` when the caller did not pass
        ``--subscription``. Returns an empty list on any failure so the
        caller can render a clear error and move on.
        """
        from azure.mgmt.subscription.aio import SubscriptionClient

        subs: list[str] = []
        try:
            async with SubscriptionClient(self.credential()) as client:
                async for s in client.subscriptions.list():
                    if getattr(s, "state", None) in (None, "Enabled"):
                        sub_id = getattr(s, "subscription_id", None)
                        if sub_id:
                            subs.append(sub_id)
        except Exception:  # noqa: BLE001
            return []
        return subs
