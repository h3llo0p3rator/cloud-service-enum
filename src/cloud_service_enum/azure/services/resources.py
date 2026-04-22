"""Resource groups and generic resources in a subscription."""

from __future__ import annotations

from azure.mgmt.resource.resources.aio import ResourceManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class ResourcesService(AzureService):
    service_name = "resources"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        async with ResourceManagementClient(auth.credential(), subscription_id) as client:
            groups = await iter_async(client.resource_groups.list())
            resources = await iter_async(client.resources.list())
        for g in groups:
            result.resources.append(
                {
                    "kind": "resource-group",
                    "id": g.id,
                    "name": g.name,
                    "location": g.location,
                    "subscription": subscription_id,
                }
            )
        if self.is_focused_on():
            for r in resources:
                row = {
                    "kind": "resource",
                    "id": r.id,
                    "name": r.name,
                    "type": r.type,
                    "location": r.location,
                    "subscription": subscription_id,
                    "tags": r.tags,
                }
                attach_identity(row, r)
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "resource_group_count": len(groups),
            "resource_count": len(resources),
        }
