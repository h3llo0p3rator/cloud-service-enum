"""Cosmos DB accounts."""

from __future__ import annotations

from azure.mgmt.cosmosdb.aio import CosmosDBManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class CosmosDbService(AzureService):
    service_name = "cosmosdb"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        from cloud_service_enum.core.secrets import mask

        focused = self.is_focused_on()
        async with CosmosDBManagementClient(auth.credential(), subscription_id) as client:
            accounts = await iter_async(client.database_accounts.list())
            for a in accounts:
                row = {
                    "kind": "account",
                    "id": a.id,
                    "name": a.name,
                    "location": a.location,
                    "subscription": subscription_id,
                    "kind": a.kind,
                    "public_network_access": a.public_network_access,
                    "key_based_metadata_write_access": a.disable_key_based_metadata_write_access,
                    "local_auth_disabled": a.disable_local_auth,
                    "ip_rules": [r.ip_address_or_range for r in (a.ip_rules or [])],
                    "virtual_network_rules": [v.id for v in (a.virtual_network_rules or [])],
                    "enable_automatic_failover": a.enable_automatic_failover,
                }
                attach_identity(row, a)
                if focused:
                    rg = a.id.split("/")[4]
                    try:
                        keys = await client.database_accounts.list_keys(rg, a.name)
                        if keys:
                            row["env_vars"] = {
                                "primary_master_key": mask(keys.primary_master_key or ""),
                                "secondary_master_key": mask(
                                    keys.secondary_master_key or ""
                                ),
                                "primary_readonly_master_key": mask(
                                    keys.primary_readonly_master_key or ""
                                ),
                                "secondary_readonly_master_key": mask(
                                    keys.secondary_readonly_master_key or ""
                                ),
                            }
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "account_count": len(accounts),
            "accounts_with_local_auth": sum(1 for a in accounts if not a.disable_local_auth),
        }
