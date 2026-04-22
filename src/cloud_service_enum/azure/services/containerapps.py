"""Azure Container Apps."""

from __future__ import annotations

from azure.mgmt.appcontainers.aio import ContainerAppsAPIClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class ContainerAppsService(AzureService):
    service_name = "containerapps"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        secret_scan = bool(self.scope and self.scope.secret_scan)
        async with ContainerAppsAPIClient(auth.credential(), subscription_id) as client:
            apps = await iter_async(client.container_apps.list_by_subscription())
            envs = await iter_async(client.managed_environments.list_by_subscription())
        for a in apps:
            ingress = a.configuration.ingress if a.configuration else None
            row = {
                "kind": "container-app",
                "id": a.id,
                "name": a.name,
                "location": a.location,
                "subscription": subscription_id,
                "provisioning_state": a.provisioning_state,
                "environment_id": a.managed_environment_id,
                "external_ingress": ingress.external if ingress else None,
                "target_port": ingress.target_port if ingress else None,
            }
            attach_identity(row, a)
            if focused:
                env_vars: dict[str, str] = {}
                secret_refs: list[str] = []
                template = getattr(a, "template", None)
                for c in (getattr(template, "containers", None) or []):
                    for ev in getattr(c, "env", None) or []:
                        if getattr(ev, "secret_ref", None):
                            secret_refs.append(f"{c.name}.{ev.name}->{ev.secret_ref}")
                        else:
                            env_vars[f"{c.name}.{ev.name}"] = ev.value or ""
                if env_vars:
                    row["env_vars"] = env_vars
                    if secret_scan:
                        from cloud_service_enum.core.secrets import scan_mapping

                        hits = scan_mapping(a.name, env_vars)
                        if hits:
                            row["secrets_found"] = [h.as_dict() for h in hits]
                if secret_refs:
                    row["secret_refs"] = secret_refs
            result.resources.append(row)
        for e in envs:
            result.resources.append(
                {
                    "kind": "environment",
                    "id": e.id,
                    "name": e.name,
                    "location": e.location,
                    "subscription": subscription_id,
                    "vnet_internal": (e.vnet_configuration.internal if e.vnet_configuration else None),
                    "zone_redundant": e.zone_redundant,
                }
            )
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "app_count": len(apps),
            "environment_count": len(envs),
            "apps_with_external_ingress": sum(
                1 for a in apps if a.configuration and a.configuration.ingress and a.configuration.ingress.external
            ),
        }
