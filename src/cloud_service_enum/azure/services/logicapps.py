"""Logic Apps workflows."""

from __future__ import annotations

from azure.mgmt.logic.aio import LogicManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class LogicAppsService(AzureService):
    service_name = "logicapps"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with LogicManagementClient(auth.credential(), subscription_id) as client:
            workflows = await iter_async(client.workflows.list_by_subscription())
            for w in workflows:
                row = {
                    "kind": "workflow",
                    "id": w.id,
                    "name": w.name,
                    "location": w.location,
                    "subscription": subscription_id,
                    "state": w.state,
                    "access_endpoint": w.access_endpoint,
                    "sku": w.sku.name if w.sku else None,
                }
                attach_identity(row, w)
                if focused:
                    rg = w.id.split("/")[4]
                    try:
                        full = await client.workflows.get(rg, w.name)
                        if full and full.definition:
                            row["definition"] = (
                                full.definition
                                if isinstance(full.definition, (dict, list))
                                else dict(full.definition)
                            )
                            row["definition_language"] = "json"
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "workflow_count": len(workflows),
            "enabled_workflows": sum(1 for w in workflows if w.state == "Enabled"),
        }
