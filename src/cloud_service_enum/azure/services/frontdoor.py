"""Azure Front Door profiles."""

from __future__ import annotations

from azure.mgmt.cdn.aio import CdnManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class FrontDoorService(AzureService):
    service_name = "frontdoor"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with CdnManagementClient(auth.credential(), subscription_id) as client:
            profiles = await iter_async(client.profiles.list())
            for p in profiles:
                if p.sku and "AzureFrontDoor" not in (p.sku.name or ""):
                    continue
                row = {
                    "kind": "profile",
                    "id": p.id,
                    "name": p.name,
                    "location": p.location,
                    "subscription": subscription_id,
                    "sku": p.sku.name if p.sku else None,
                    "provisioning_state": p.provisioning_state,
                    "resource_state": p.resource_state,
                }
                attach_identity(row, p)
                if focused:
                    rg = p.id.split("/")[4]
                    try:
                        endpoints = await iter_async(
                            client.afd_endpoints.list_by_profile(rg, p.name)
                        )
                        row["endpoints"] = [
                            {
                                "name": e.name,
                                "host_name": e.host_name,
                                "enabled_state": e.enabled_state,
                            }
                            for e in endpoints
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        policies = await iter_async(
                            client.security_policies.list_by_profile(rg, p.name)
                        )
                        row["security_policies"] = [pol.name for pol in policies]
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "profile_count": len([r for r in result.resources if r.get("kind") == "profile"]),
        }
