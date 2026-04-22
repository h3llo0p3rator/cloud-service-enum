"""Key Vaults."""

from __future__ import annotations

from azure.mgmt.keyvault.aio import KeyVaultManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class KeyVaultService(AzureService):
    service_name = "keyvault"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with KeyVaultManagementClient(auth.credential(), subscription_id) as client:
            vaults = await iter_async(client.vaults.list_by_subscription())
        for v in vaults:
            props = v.properties
            row = {
                "kind": "key-vault",
                "id": v.id,
                "name": v.name,
                "location": v.location,
                "subscription": subscription_id,
                "sku": props.sku.name if props and props.sku else None,
                "soft_delete_enabled": getattr(props, "enable_soft_delete", None),
                "purge_protection": getattr(props, "enable_purge_protection", None),
                "rbac_authorization": getattr(props, "enable_rbac_authorization", None),
                "public_network_access": getattr(props, "public_network_access", None),
                "network_default_action": (
                    props.network_acls.default_action if props and props.network_acls else None
                ),
            }
            if focused and props and getattr(props, "access_policies", None):
                row["role_bindings"] = [
                    {
                        "principal": ap.object_id,
                        "role": ", ".join(_perms(ap)),
                        "condition": "",
                    }
                    for ap in props.access_policies or []
                ]
            result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "vault_count": len(vaults),
            "vaults_without_purge_protection": sum(
                1 for r in result.resources if r.get("kind") == "key-vault" and not r.get("purge_protection")
            ),
        }


def _perms(ap) -> list[str]:
    """Flatten the per-permission-type lists into a single list."""
    perms = ap.permissions
    if not perms:
        return []
    out: list[str] = []
    for attr, prefix in (("keys", "keys"), ("secrets", "secrets"), ("certificates", "certs"), ("storage", "storage")):
        for p in getattr(perms, attr, None) or []:
            out.append(f"{prefix}:{p}")
    return out
