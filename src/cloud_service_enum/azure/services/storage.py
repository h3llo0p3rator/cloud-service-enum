"""Storage accounts, blob services and containers with CIS v5 fields."""

from __future__ import annotations

from azure.mgmt.storage.aio import StorageManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class StorageService(AzureService):
    service_name = "storage"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with StorageManagementClient(auth.credential(), subscription_id) as client:
            accounts = await iter_async(client.storage_accounts.list())
            enriched: list[dict] = []
            for a in accounts:
                rg = a.id.split("/")[4]
                blob_props = None
                try:
                    blob_props = await client.blob_services.get_service_properties(rg, a.name)
                except Exception:  # noqa: BLE001
                    pass
                containers = []
                try:
                    containers = await iter_async(client.blob_containers.list(rg, a.name))
                except Exception:  # noqa: BLE001
                    pass
                row = {
                        "kind": "storage-account",
                        "id": a.id,
                        "name": a.name,
                        "location": a.location,
                        "subscription": subscription_id,
                        "sku": a.sku.name if a.sku else None,
                        "kind_class": a.kind,
                        "https_only": a.enable_https_traffic_only,
                        "min_tls_version": a.minimum_tls_version,
                        "allow_blob_public_access": a.allow_blob_public_access,
                        "allow_shared_key_access": a.allow_shared_key_access,
                        "public_network_access": a.public_network_access,
                        "encryption_key_source": a.encryption.key_source if a.encryption else None,
                        "infrastructure_encryption": (
                            a.encryption.require_infrastructure_encryption if a.encryption else None
                        ),
                        "blob_soft_delete": (
                            (blob_props.delete_retention_policy.enabled if blob_props and blob_props.delete_retention_policy else None)
                        ),
                        "container_count": len(containers),
                        "public_containers": sum(
                            1 for c in containers if c.public_access and c.public_access != "None"
                        ),
                        "network_default_action": a.network_rule_set.default_action if a.network_rule_set else None,
                }
                attach_identity(row, a)
                if focused:
                    await self._enrich(client, rg, a, row)
                enriched.append(row)
        result.resources.extend(enriched)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "storage_account_count": len(enriched),
            "accounts_without_https_only": sum(1 for r in enriched if not r.get("https_only")),
            "accounts_allowing_public_blob": sum(1 for r in enriched if r.get("allow_blob_public_access")),
        }

    @staticmethod
    async def _enrich(client: StorageManagementClient, rg: str, a, row: dict) -> None:
        """Pull keys + management policy + private endpoint connections (deep)."""
        from cloud_service_enum.core.secrets import mask

        try:
            keys = await client.storage_accounts.list_keys(rg, a.name)
            if keys and keys.keys:
                row["env_vars"] = {
                    f"key_{k.key_name}": mask(k.value or "") for k in keys.keys
                }
        except Exception:  # noqa: BLE001
            pass
        try:
            policy = await client.management_policies.get(rg, a.name, "default")
            if policy and policy.policy:
                body = policy.policy
                row["policy_document"] = (
                    body.serialize() if hasattr(body, "serialize") else dict(body)
                )
        except Exception:  # noqa: BLE001
            pass
        try:
            pec = await iter_async(
                client.private_endpoint_connections.list(rg, a.name)
            )
            row["private_endpoints"] = [
                {
                    "id": p.id,
                    "name": p.name,
                    "state": (
                        p.private_link_service_connection_state.status
                        if p.private_link_service_connection_state
                        else None
                    ),
                }
                for p in pec or []
            ]
        except Exception:  # noqa: BLE001
            pass
