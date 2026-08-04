"""GCP authentication covering service accounts, ADC, impersonation and WIF."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import httpx
from google.auth import default as adc_default
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials as UserCredentials

from cloud_service_enum.core.auth import CloudAuthenticator, IdentitySummary
from cloud_service_enum.core.errors import AuthenticationError

SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"


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
            # Pre-minted tokens (metadata API, gcloud print-access-token, etc.)
            # cannot be refreshed — do not attach refresh fields or scopes that
            # would push google-auth into a refresh path.
            return (
                UserCredentials(
                    token=cfg.access_token,
                    quota_project_id=cfg.quota_project or cfg.project_id,
                ),
                None,
            )
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

    @staticmethod
    def _introspect_access_token(token: str) -> dict[str, Any]:
        """Validate a bearer token via Google's tokeninfo endpoint."""
        try:
            resp = httpx.get(
                _TOKENINFO_URL,
                params={"access_token": token},
                timeout=15.0,
            )
        except httpx.HTTPError as exc:
            raise AuthenticationError(f"failed to validate GCP access token: {exc}") from exc
        if resp.status_code != 200:
            detail = resp.text.strip() or resp.reason_phrase
            raise AuthenticationError(
                f"GCP access token rejected by tokeninfo ({resp.status_code}): {detail}"
            )
        return resp.json()

    async def credentials(self) -> Any:
        if self._credentials is None:
            self._credentials, self._principal = await asyncio.to_thread(self._build)
        return self._credentials

    async def test(self) -> IdentitySummary:
        try:
            creds = await self.credentials()
            if self.config.method == "access-token":
                info = await asyncio.to_thread(
                    self._introspect_access_token, self.config.access_token or ""
                )
                self._principal = (
                    info.get("email")
                    or info.get("sub")
                    or "access-token"
                )
            else:
                await asyncio.to_thread(creds.refresh, Request())
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError(f"failed to refresh GCP credentials: {exc}") from exc

        return IdentitySummary(
            provider="gcp",
            principal=self._principal or "unknown",
            display_name=self._principal,
            tenant_or_account=self.config.project_id or self.config.quota_project,
            auth_method=self.config.method,
        )

    async def discover_projects(self) -> list[str]:
        """List active project ids visible to the credential.

        Used by :func:`run_provider` when the caller did not pass
        ``--project`` / ``--projects``. Returns an empty list on failure.
        """
        try:
            from google.cloud import resourcemanager_v3
        except ImportError:
            return []

        creds = await self.credentials()

        def _list() -> list[str]:
            client = resourcemanager_v3.ProjectsClient(credentials=creds)
            out: list[str] = []
            for project in client.search_projects():
                state = getattr(project.state, "name", str(project.state)).upper()
                if "DELETE" in state:
                    continue
                if project.project_id:
                    out.append(project.project_id)
            return out

        try:
            return await asyncio.to_thread(_list)
        except Exception:  # noqa: BLE001
            return []

    async def close(self) -> None:
        self._credentials = None
