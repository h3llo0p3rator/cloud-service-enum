"""Azure API Management services."""

from __future__ import annotations

from azure.mgmt.apimanagement.aio import ApiManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class ApimService(AzureService):
    service_name = "apim"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with ApiManagementClient(auth.credential(), subscription_id) as client:
            services = await iter_async(client.api_management_service.list())
            for s in services:
                row = {
                    "kind": "apim-service",
                    "id": s.id,
                    "name": s.name,
                    "location": s.location,
                    "subscription": subscription_id,
                    "sku": s.sku.name if s.sku else None,
                    "capacity": s.sku.capacity if s.sku else None,
                    "gateway_url": s.gateway_url,
                    "virtual_network_type": s.virtual_network_type,
                    "public_network_access": s.public_network_access,
                    "disable_gateway": s.disable_gateway,
                    "enable_client_certificate": s.enable_client_certificate,
                    "platform_version": s.platform_version,
                }
                attach_identity(row, s)
                if focused:
                    rg = s.id.split("/")[4]
                    try:
                        apis = await iter_async(client.api.list_by_service(rg, s.name))
                        row["apis"] = [
                            {
                                "name": a.name,
                                "path": a.path,
                                "service_url": a.service_url,
                                "subscription_required": a.subscription_required,
                                "protocols": a.protocols,
                            }
                            for a in apis
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        named = await iter_async(
                            client.named_value.list_by_service(rg, s.name)
                        )
                        row["env_vars"] = {
                            n.display_name: ("<secret>" if n.secret else (n.value or ""))
                            for n in named
                        }
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "service_count": len(services),
        }
