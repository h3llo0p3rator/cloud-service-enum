"""Event Hubs namespaces."""

from __future__ import annotations

from azure.mgmt.eventhub.aio import EventHubManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class EventHubsService(AzureService):
    service_name = "eventhubs"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        from cloud_service_enum.core.secrets import mask

        focused = self.is_focused_on()
        async with EventHubManagementClient(auth.credential(), subscription_id) as client:
            namespaces = await iter_async(client.namespaces.list())
            for n in namespaces:
                row = {
                    "kind": "namespace",
                    "id": n.id,
                    "name": n.name,
                    "location": n.location,
                    "subscription": subscription_id,
                    "sku": n.sku.name if n.sku else None,
                    "zone_redundant": n.zone_redundant,
                    "public_network_access": n.public_network_access,
                    "minimum_tls_version": n.minimum_tls_version,
                    "disable_local_auth": n.disable_local_auth,
                    "kafka_enabled": n.kafka_enabled,
                }
                attach_identity(row, n)
                if focused:
                    rg = n.id.split("/")[4]
                    try:
                        rules = await iter_async(
                            client.namespaces.list_authorization_rules(rg, n.name)
                        )
                        env_vars: dict[str, str] = {}
                        for rule in rules:
                            try:
                                keys = await client.namespaces.list_keys(
                                    rg, n.name, rule.name
                                )
                                env_vars[f"{rule.name}.primaryConnectionString"] = mask(
                                    keys.primary_connection_string or ""
                                )
                                env_vars[f"{rule.name}.secondaryConnectionString"] = mask(
                                    keys.secondary_connection_string or ""
                                )
                            except Exception:  # noqa: BLE001
                                continue
                        if env_vars:
                            row["env_vars"] = env_vars
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        hubs = await iter_async(
                            client.event_hubs.list_by_namespace(rg, n.name)
                        )
                        row["event_hubs"] = [
                            {
                                "name": h.name,
                                "partition_count": h.partition_count,
                                "status": h.status,
                                "retention_hours": h.message_retention_in_days * 24
                                if h.message_retention_in_days
                                else None,
                            }
                            for h in hubs
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "namespace_count": len(namespaces),
        }
