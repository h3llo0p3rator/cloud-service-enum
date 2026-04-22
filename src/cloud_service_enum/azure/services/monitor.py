"""Azure Monitor diagnostic settings and activity log alerts."""

from __future__ import annotations

from azure.mgmt.monitor.aio import MonitorManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class MonitorService(AzureService):
    service_name = "monitor"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        async with MonitorManagementClient(auth.credential(), subscription_id) as client:
            alerts = await iter_async(client.activity_log_alerts.list_by_subscription_id())
            log_profiles = []
            try:
                log_profiles = await iter_async(client.log_profiles.list())
            except Exception:  # noqa: BLE001
                pass
        for a in alerts:
            result.resources.append(
                {
                    "kind": "activity-log-alert",
                    "id": a.id,
                    "name": a.name,
                    "subscription": subscription_id,
                    "enabled": a.enabled,
                    "scopes": a.scopes,
                    "condition": [getattr(c, "field", None) for c in (a.condition.all_of if a.condition else [])],
                }
            )
        for lp in log_profiles:
            result.resources.append(
                {
                    "kind": "log-profile",
                    "id": lp.id,
                    "name": lp.name,
                    "subscription": subscription_id,
                    "retention_days": lp.retention_policy.days if lp.retention_policy else None,
                    "storage_account_id": lp.storage_account_id,
                    "locations": lp.locations,
                    "categories": lp.categories,
                }
            )
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "alert_count": len(alerts),
            "log_profile_count": len(log_profiles),
        }
