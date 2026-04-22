"""VPC networks, subnets, firewalls and routes."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class VpcService(GcpService):
    service_name = "vpc"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import compute_v1
        except ImportError:
            missing_sdk(result, "google-cloud-compute")
            return
        networks = safe_list(compute_v1.NetworksClient(credentials=credentials).list(project=project_id))
        subnets_pages = compute_v1.SubnetworksClient(credentials=credentials).aggregated_list(
            project=project_id
        )
        firewalls = safe_list(compute_v1.FirewallsClient(credentials=credentials).list(project=project_id))
        routes = safe_list(compute_v1.RoutesClient(credentials=credentials).list(project=project_id))

        for n in networks:
            result.resources.append(
                {
                    "kind": "network",
                    "id": str(n.id),
                    "name": n.name,
                    "project": project_id,
                    "auto_create_subnetworks": n.auto_create_subnetworks,
                    "routing_mode": n.routing_config.routing_mode if n.routing_config else None,
                }
            )
        subnet_count = 0
        flow_logs_enabled = 0
        for _region, scoped in subnets_pages:
            for s in scoped.subnetworks or []:
                subnet_count += 1
                if s.enable_flow_logs:
                    flow_logs_enabled += 1
                result.resources.append(
                    {
                        "kind": "subnet",
                        "id": str(s.id),
                        "name": s.name,
                        "project": project_id,
                        "region": s.region.split("/")[-1] if s.region else None,
                        "ip_cidr_range": s.ip_cidr_range,
                        "private_google_access": s.private_ip_google_access,
                        "flow_logs_enabled": s.enable_flow_logs,
                    }
                )
        focused = self.is_focused_on()
        world_open_firewalls = 0
        for f in firewalls:
            source_ranges = list(f.source_ranges or [])
            world_open = any(sr in {"0.0.0.0/0", "::/0"} for sr in source_ranges) and f.direction == "INGRESS"
            if world_open:
                world_open_firewalls += 1
            row = {
                "kind": "firewall",
                "id": str(f.id),
                "name": f.name,
                "project": project_id,
                "direction": f.direction,
                "source_ranges": source_ranges,
                "target_tags": list(f.target_tags or []),
                "allowed": [{"protocol": a.I_p_protocol, "ports": list(a.ports)} for a in f.allowed],
                "denied": [{"protocol": a.I_p_protocol, "ports": list(a.ports)} for a in f.denied],
                "disabled": f.disabled,
                "world_open": world_open,
            }
            if focused:
                row["firewall_rules"] = [
                    {
                        "name": f.name,
                        "priority": f.priority,
                        "direction": f.direction,
                        "src": ", ".join(source_ranges) or "-",
                        "dst": ", ".join(f.destination_ranges or []) or "-",
                        "action": "allow" if f.allowed else "deny",
                        "protocol": ", ".join(
                            a.I_p_protocol for a in (f.allowed or f.denied or [])
                        )
                        or "-",
                        "ports": ", ".join(
                            ", ".join(a.ports or [])
                            for a in (f.allowed or f.denied or [])
                            if a.ports
                        ) or "-",
                        "target_tags": ", ".join(f.target_tags or []) or "-",
                        "target_sa": ", ".join(f.target_service_accounts or []) or "-",
                    }
                ]
            result.resources.append(row)
        for r in routes:
            result.resources.append(
                {
                    "kind": "route",
                    "id": str(r.id),
                    "name": r.name,
                    "project": project_id,
                    "dest_range": r.dest_range,
                    "next_hop": r.next_hop_gateway or r.next_hop_ip or r.next_hop_instance,
                }
            )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "network_count": len(networks),
            "subnet_count": subnet_count,
            "subnets_with_flow_logs": flow_logs_enabled,
            "world_open_firewall_rules": world_open_firewalls,
        }
