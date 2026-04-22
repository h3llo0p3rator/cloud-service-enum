"""Cloud Monitoring alert policies and notification channels."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class MonitoringService(GcpService):
    service_name = "monitoring"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import monitoring_v3
        except ImportError:
            missing_sdk(result, "google-cloud-monitoring")
            return
        alerts = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        channels = monitoring_v3.NotificationChannelServiceClient(credentials=credentials)
        name = f"projects/{project_id}"
        policies = safe_list(alerts.list_alert_policies(name=name))
        channel_list = safe_list(channels.list_notification_channels(name=name))
        for p in policies:
            result.resources.append(
                {
                    "kind": "alert-policy",
                    "id": p.name,
                    "project": project_id,
                    "display_name": p.display_name,
                    "enabled": p.enabled.value if hasattr(p.enabled, "value") else bool(p.enabled),
                    "condition_count": len(p.conditions),
                    "notification_channels": list(p.notification_channels),
                }
            )
        for c in channel_list:
            result.resources.append(
                {
                    "kind": "notification-channel",
                    "id": c.name,
                    "project": project_id,
                    "type": c.type_,
                    "verification_status": c.verification_status.name,
                    "enabled": c.enabled.value if hasattr(c.enabled, "value") else bool(c.enabled),
                }
            )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "alert_policy_count": len(policies),
            "notification_channel_count": len(channel_list),
        }
