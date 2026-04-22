"""AKS managed Kubernetes clusters."""

from __future__ import annotations

from azure.mgmt.containerservice.aio import ContainerServiceClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class AksService(AzureService):
    service_name = "aks"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with ContainerServiceClient(auth.credential(), subscription_id) as client:
            clusters = await iter_async(client.managed_clusters.list())
            for c in clusters:
                api = c.api_server_access_profile
                row = {
                    "kind": "cluster",
                    "id": c.id,
                    "name": c.name,
                    "location": c.location,
                    "subscription": subscription_id,
                    "k8s_version": c.kubernetes_version,
                    "private_cluster": getattr(api, "enable_private_cluster", False) if api else False,
                    "authorized_ip_ranges": getattr(api, "authorized_ip_ranges", None) if api else None,
                    "rbac_enabled": c.enable_rbac,
                    "aad_profile": bool(c.aad_profile),
                    "network_plugin": c.network_profile.network_plugin if c.network_profile else None,
                    "network_policy": c.network_profile.network_policy if c.network_profile else None,
                    "node_pool_count": len(c.agent_pool_profiles or []),
                }
                attach_identity(row, c)
                if focused:
                    row["node_resource_group"] = c.node_resource_group
                    row["workload_identity"] = bool(
                        getattr(c, "security_profile", None)
                        and getattr(c.security_profile, "workload_identity", None)
                        and c.security_profile.workload_identity.enabled
                    )
                    row["node_pools"] = [
                        {
                            "name": pool.name,
                            "vm_size": pool.vm_size,
                            "os_type": pool.os_type,
                            "mode": pool.mode,
                            "kubelet_identity": getattr(c, "identity_profile", None)
                            and (c.identity_profile or {}).get("kubeletidentity", {}),
                            "max_pods": pool.max_pods,
                            "node_taints": pool.node_taints,
                            "auto_scaling": pool.enable_auto_scaling,
                        }
                        for pool in c.agent_pool_profiles or []
                    ]
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "cluster_count": len(clusters),
            "public_clusters": sum(
                1 for c in clusters if not (c.api_server_access_profile and c.api_server_access_profile.enable_private_cluster)
            ),
        }
