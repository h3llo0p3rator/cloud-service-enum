"""VNets, NSGs, public IPs and network watchers."""

from __future__ import annotations

from azure.mgmt.network.aio import NetworkManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class NetworkService(AzureService):
    service_name = "network"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        async with NetworkManagementClient(auth.credential(), subscription_id) as client:
            vnets = await iter_async(client.virtual_networks.list_all())
            nsgs = await iter_async(client.network_security_groups.list_all())
            public_ips = await iter_async(client.public_ip_addresses.list_all())
            watchers = await iter_async(client.network_watchers.list_all())

        for v in vnets:
            result.resources.append(
                {
                    "kind": "vnet",
                    "id": v.id,
                    "name": v.name,
                    "location": v.location,
                    "subscription": subscription_id,
                    "address_prefixes": v.address_space.address_prefixes if v.address_space else None,
                    "ddos_protection": v.enable_ddos_protection,
                    "flow_timeout": v.flow_timeout_in_minutes,
                    "subnet_count": len(v.subnets or []),
                }
            )
        focused = self.is_focused_on()
        world_open = 0
        for n in nsgs:
            rules = n.security_rules or []
            open_ports = [
                {
                    "name": r.name,
                    "protocol": r.protocol,
                    "direction": r.direction,
                    "destination_port": r.destination_port_range,
                    "source": r.source_address_prefix,
                }
                for r in rules
                if r.access == "Allow"
                and r.direction == "Inbound"
                and r.source_address_prefix in {"*", "Internet", "0.0.0.0/0"}
            ]
            if open_ports:
                world_open += 1
            row = {
                "kind": "nsg",
                "id": n.id,
                "name": n.name,
                "location": n.location,
                "subscription": subscription_id,
                "world_open_ports": open_ports,
            }
            if focused:
                row["firewall_rules"] = [
                    {
                        "name": r.name,
                        "priority": r.priority,
                        "access": r.access,
                        "direction": r.direction,
                        "protocol": r.protocol,
                        "src": r.source_address_prefix
                        or ", ".join(r.source_address_prefixes or []),
                        "src_port": r.source_port_range
                        or ", ".join(r.source_port_ranges or []),
                        "dst": r.destination_address_prefix
                        or ", ".join(r.destination_address_prefixes or []),
                        "dst_port": r.destination_port_range
                        or ", ".join(r.destination_port_ranges or []),
                    }
                    for r in rules
                ]
            result.resources.append(row)
        for p in public_ips:
            result.resources.append(
                {
                    "kind": "public-ip",
                    "id": p.id,
                    "name": p.name,
                    "location": p.location,
                    "subscription": subscription_id,
                    "ip": p.ip_address,
                    "sku": p.sku.name if p.sku else None,
                    "ddos_settings": bool(p.ddos_settings),
                }
            )
        for w in watchers:
            result.resources.append(
                {
                    "kind": "network-watcher",
                    "id": w.id,
                    "name": w.name,
                    "location": w.location,
                    "subscription": subscription_id,
                    "provisioning_state": w.provisioning_state,
                }
            )
        locations_with_watchers = {w.location for w in watchers}
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "vnet_count": len(vnets),
            "nsg_count": len(nsgs),
            "nsgs_open_to_world": world_open,
            "public_ip_count": len(public_ips),
            "locations_without_watcher": sorted(
                {v.location for v in vnets} - locations_with_watchers
            ),
        }
