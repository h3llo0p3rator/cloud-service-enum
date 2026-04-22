"""Azure Bastion hosts."""

from __future__ import annotations

from azure.mgmt.network.aio import NetworkManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class BastionService(AzureService):
    service_name = "bastion"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        async with NetworkManagementClient(auth.credential(), subscription_id) as client:
            hosts = await iter_async(client.bastion_hosts.list())
        for h in hosts:
            result.resources.append(
                {
                    "kind": "bastion-host",
                    "id": h.id,
                    "name": h.name,
                    "location": h.location,
                    "subscription": subscription_id,
                    "sku": h.sku.name if h.sku else None,
                    "scale_units": h.scale_units,
                    "dns_name": h.dns_name,
                    "tunneling_enabled": getattr(h, "enable_tunneling", None),
                    "ip_connect_enabled": getattr(h, "enable_ip_connect", None),
                    "shareable_link_enabled": getattr(h, "enable_shareable_link", None),
                }
            )
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "host_count": len(hosts),
        }
