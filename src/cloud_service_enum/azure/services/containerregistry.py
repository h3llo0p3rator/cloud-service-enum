"""Azure Container Registries."""

from __future__ import annotations

from azure.mgmt.containerregistry.aio import ContainerRegistryManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class ContainerRegistryService(AzureService):
    service_name = "containerregistry"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        from cloud_service_enum.core.secrets import mask

        focused = self.is_focused_on()
        async with ContainerRegistryManagementClient(auth.credential(), subscription_id) as client:
            registries = await iter_async(client.registries.list())
            for r in registries:
                row = {
                    "kind": "registry",
                    "id": r.id,
                    "name": r.name,
                    "location": r.location,
                    "subscription": subscription_id,
                    "sku": r.sku.name if r.sku else None,
                    "admin_user_enabled": r.admin_user_enabled,
                    "public_network_access": r.public_network_access,
                    "zone_redundancy": r.zone_redundancy,
                    "anonymous_pull_enabled": r.anonymous_pull_enabled,
                    "login_server": r.login_server,
                }
                attach_identity(row, r)
                if focused:
                    rg = r.id.split("/")[4]
                    if r.admin_user_enabled:
                        try:
                            creds = await client.registries.list_credentials(rg, r.name)
                            if creds:
                                row["env_vars"] = {
                                    "username": creds.username or "",
                                    **{
                                        f"password[{i}]": mask(p.value or "")
                                        for i, p in enumerate(creds.passwords or [])
                                    },
                                }
                        except Exception:  # noqa: BLE001
                            pass
                    try:
                        webhooks = await iter_async(
                            client.webhooks.list(rg, r.name)
                        )
                        row["webhooks"] = [
                            {
                                "name": w.name,
                                "actions": w.actions,
                                "scope": w.scope,
                                "status": w.status,
                            }
                            for w in webhooks
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "registry_count": len(registries),
            "registries_with_admin": sum(1 for r in registries if r.admin_user_enabled),
        }
