"""Log Analytics workspaces."""

from __future__ import annotations

from azure.mgmt.loganalytics.aio import LogAnalyticsManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class LogAnalyticsService(AzureService):
    service_name = "loganalytics"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        from cloud_service_enum.core.secrets import mask

        focused = self.is_focused_on()
        async with LogAnalyticsManagementClient(auth.credential(), subscription_id) as client:
            workspaces = await iter_async(client.workspaces.list())
            for w in workspaces:
                row = {
                    "kind": "workspace",
                    "id": w.id,
                    "name": w.name,
                    "location": w.location,
                    "subscription": subscription_id,
                    "retention_days": w.retention_in_days,
                    "sku": w.sku.name if w.sku else None,
                    "public_network_access_for_ingestion": w.public_network_access_for_ingestion,
                    "public_network_access_for_query": w.public_network_access_for_query,
                    "workspace_id": w.customer_id,
                }
                if focused:
                    rg = w.id.split("/")[4]
                    try:
                        keys = await client.shared_keys.get_shared_keys(rg, w.name)
                        row["env_vars"] = {
                            "primary_shared_key": mask(keys.primary_shared_key or ""),
                            "secondary_shared_key": mask(
                                keys.secondary_shared_key or ""
                            ),
                        }
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        sources = await iter_async(
                            client.data_sources.list_by_workspace(rg, w.name, filter="")
                        )
                        row["data_sources"] = [
                            {"name": s.name, "kind": s.kind} for s in sources
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "workspace_count": len(workspaces),
        }
