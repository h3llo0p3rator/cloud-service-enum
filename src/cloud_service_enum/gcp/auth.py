"""GCP authentication covering service accounts, ADC, impersonation and WIF."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from google.auth import default as adc_default
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials as UserCredentials

from cloud_service_enum.core.auth import CloudAuthenticator, IdentitySummary
from cloud_service_enum.core.errors import AuthenticationError

SCOPE = "https://www.googleapis.com/auth/cloud-platform"


@dataclass
class GcpAuthConfig:
    """Inputs describing how to build GCP credentials."""

    service_account_file: str | None = None
    service_account_json: str | None = None
    access_token: str | None = None
    impersonate_service_account: str | None = None
    workload_identity_config: str | None = None
    quota_project: str | None = None
    project_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def method(self) -> str:
        if self.service_account_file or self.service_account_json:
            return "service-account"
        if self.access_token:
            return "access-token"
        if self.impersonate_service_account:
            return "impersonation"
        if self.workload_identity_config:
            return "workload-identity-federation"
        return "application-default"


class GcpAuthenticator(CloudAuthenticator):
    """Synchronous Google auth wrapped for async callers via ``to_thread``."""

    provider = "gcp"

    def __init__(self, config: GcpAuthConfig | None = None) -> None:
        self.config = config or GcpAuthConfig()
        self._credentials: Any = None
        self._project: str | None = None
        self._principal: str | None = None

    def _build(self) -> tuple[Any, str | None]:
        cfg = self.config
        if cfg.service_account_json:
            info = json.loads(cfg.service_account_json)
            creds = service_account.Credentials.from_service_account_info(info, scopes=[SCOPE])
            if not cfg.project_id and info.get("project_id"):
                cfg.project_id = info["project_id"]
            return creds, info.get("client_email")
        if cfg.service_account_file:
            creds = service_account.Credentials.from_service_account_file(
                cfg.service_account_file, scopes=[SCOPE]
            )
            with open(cfg.service_account_file) as fh:
                info = json.load(fh)
            if not cfg.project_id and info.get("project_id"):
                cfg.project_id = info["project_id"]
            return creds, info.get("client_email")
        if cfg.access_token:
            return UserCredentials(token=cfg.access_token, scopes=[SCOPE]), None
        if cfg.impersonate_service_account:
            from google.auth import impersonated_credentials
            source, _ = adc_default(scopes=[SCOPE])
            creds = impersonated_credentials.Credentials(
                source_credentials=source,
                target_principal=cfg.impersonate_service_account,
                target_scopes=[SCOPE],
            )
            return creds, cfg.impersonate_service_account
        creds, project = adc_default(scopes=[SCOPE])
        return creds, f"ADC (project={project})"

    async def credentials(self) -> Any:
        if self._credentials is None:
            self._credentials, self._principal = await asyncio.to_thread(self._build)
        return self._credentials

    async def test(self) -> IdentitySummary:
        try:
            creds = await self.credentials()
            await asyncio.to_thread(creds.refresh, Request())
        except Exception as exc:
            raise AuthenticationError(f"failed to refresh GCP credentials: {exc}") from exc

        return IdentitySummary(
            provider="gcp",
            principal=self._principal or "unknown",
            display_name=self._principal,
            tenant_or_account=self.config.project_id or self.config.quota_project,
            auth_method=self.config.method,
        )

    async def close(self) -> None:
        self._credentials = None
