"""Azure Firewalls and firewall policies."""

from __future__ import annotations

from azure.mgmt.network.aio import NetworkManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class FirewallService(AzureService):
    service_name = "firewall"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with NetworkManagementClient(auth.credential(), subscription_id) as client:
            firewalls = await iter_async(client.azure_firewalls.list_all())
            policies = await iter_async(client.firewall_policies.list_all())
            for f in firewalls:
                row = {
                    "kind": "firewall",
                    "id": f.id,
                    "name": f.name,
                    "location": f.location,
                    "subscription": subscription_id,
                    "sku_name": f.sku.name if f.sku else None,
                    "sku_tier": f.sku.tier if f.sku else None,
                    "threat_intel_mode": f.threat_intel_mode,
                    "ip_configurations": len(f.ip_configurations or []),
                }
                if focused:
                    row["application_rules"] = [
                        {
                            "collection": coll.name,
                            "priority": coll.priority,
                            "action": coll.action.type if coll.action else None,
                            "rules": [r.as_dict() for r in coll.rules or []],
                        }
                        for coll in f.application_rule_collections or []
                    ]
                    row["network_rules"] = [
                        {
                            "collection": coll.name,
                            "priority": coll.priority,
                            "action": coll.action.type if coll.action else None,
                            "rules": [r.as_dict() for r in coll.rules or []],
                        }
                        for coll in f.network_rule_collections or []
                    ]
                    row["nat_rules"] = [
                        {
                            "collection": coll.name,
                            "priority": coll.priority,
                            "rules": [r.as_dict() for r in coll.rules or []],
                        }
                        for coll in f.nat_rule_collections or []
                    ]
                result.resources.append(row)
            for p in policies:
                prow = {
                    "kind": "firewall-policy",
                    "id": p.id,
                    "name": p.name,
                    "location": p.location,
                    "subscription": subscription_id,
                    "threat_intel_mode": p.threat_intel_mode,
                    "intrusion_mode": (p.intrusion_detection.mode if p.intrusion_detection else None),
                    "tls_inspection": bool(p.transport_security),
                }
                if focused:
                    rg = p.id.split("/")[4]
                    try:
                        groups = await iter_async(
                            client.firewall_policy_rule_collection_groups.list(rg, p.name)
                        )
                        prow["rule_collection_groups"] = [
                            {
                                "name": grp.name,
                                "priority": grp.priority,
                                "collections": [
                                    coll.as_dict()
                                    for coll in grp.rule_collections or []
                                ],
                            }
                            for grp in groups
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(prow)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "firewall_count": len(firewalls),
            "policy_count": len(policies),
        }
