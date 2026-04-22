"""Google Kubernetes Engine clusters."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk


class GkeService(GcpService):
    service_name = "gke"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import container_v1
        except ImportError:
            missing_sdk(result, "google-cloud-container")
            return
        client = container_v1.ClusterManagerClient(credentials=credentials)
        resp = client.list_clusters(parent=f"projects/{project_id}/locations/-")
        clusters = resp.clusters
        private_clusters = 0
        with_network_policy = 0
        focused = self.is_focused_on()
        for c in clusters:
            priv = c.private_cluster_config
            if priv and priv.enable_private_nodes:
                private_clusters += 1
            if c.network_policy and c.network_policy.enabled:
                with_network_policy += 1
            row = {
                "kind": "cluster",
                "id": c.self_link,
                "name": c.name,
                "project": project_id,
                "location": c.location,
                "status": c.status.name,
                "current_master_version": c.current_master_version,
                "endpoint": c.endpoint,
                "private_nodes": priv.enable_private_nodes if priv else False,
                "private_endpoint": priv.enable_private_endpoint if priv else False,
                "network_policy": c.network_policy.enabled if c.network_policy else False,
                "master_authorized_networks": (
                    c.master_authorized_networks_config.enabled
                    if c.master_authorized_networks_config
                    else False
                ),
                "workload_identity_pool": (
                    c.workload_identity_config.workload_pool if c.workload_identity_config else None
                ),
                "binary_authorization": c.binary_authorization.evaluation_mode.name if c.binary_authorization else None,
                "release_channel": c.release_channel.channel.name if c.release_channel else None,
            }
            if focused:
                row["node_pools"] = [
                    {
                        "name": np.name,
                        "machine_type": np.config.machine_type if np.config else None,
                        "service_account": np.config.service_account if np.config else None,
                        "oauth_scopes": list(np.config.oauth_scopes)
                        if np.config and np.config.oauth_scopes
                        else None,
                        "image_type": np.config.image_type if np.config else None,
                        "auto_repair": np.management.auto_repair if np.management else None,
                        "auto_upgrade": np.management.auto_upgrade if np.management else None,
                        "version": np.version,
                    }
                    for np in c.node_pools or []
                ]
                if c.master_authorized_networks_config:
                    row["authorized_networks"] = [
                        {"display_name": b.display_name, "cidr": b.cidr_block}
                        for b in c.master_authorized_networks_config.cidr_blocks or []
                    ]
                row["addons"] = (
                    {
                        "http_load_balancing_disabled": c.addons_config.http_load_balancing.disabled
                        if c.addons_config and c.addons_config.http_load_balancing
                        else None,
                        "horizontal_pod_autoscaling_disabled": c.addons_config.horizontal_pod_autoscaling.disabled
                        if c.addons_config and c.addons_config.horizontal_pod_autoscaling
                        else None,
                        "network_policy_config_disabled": c.addons_config.network_policy_config.disabled
                        if c.addons_config and c.addons_config.network_policy_config
                        else None,
                    }
                    if c.addons_config
                    else None
                )
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "cluster_count": len(clusters),
            "private_clusters": private_clusters,
            "clusters_with_network_policy": with_network_policy,
        }
