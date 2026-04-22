"""Identity-Aware Proxy resources and IAM policies."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, format_gcp_error, missing_sdk


class IapService(GcpService):
    service_name = "iap"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from googleapiclient import discovery
        except ImportError:
            missing_sdk(result, "google-api-python-client")
            return
        api = discovery.build("iap", "v1", credentials=credentials, cache_discovery=False)
        parent = f"projects/{project_id}"
        try:
            settings = api.v1().getIapSettings(name=parent).execute()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"[{project_id}] iap_settings: {format_gcp_error(exc)}")
            settings = {}
        result.resources.append(
            {
                "kind": "iap-settings",
                "id": parent,
                "project": project_id,
                "access_settings": settings.get("accessSettings"),
                "application_settings": settings.get("applicationSettings"),
            }
        )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "has_iap_settings": bool(settings),
        }
