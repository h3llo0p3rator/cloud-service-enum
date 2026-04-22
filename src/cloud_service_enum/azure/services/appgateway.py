"""Application Gateways."""

from __future__ import annotations

from azure.mgmt.network.aio import NetworkManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class AppGatewayService(AzureService):
    service_name = "appgateway"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with NetworkManagementClient(auth.credential(), subscription_id) as client:
            gateways = await iter_async(client.application_gateways.list_all())
        for g in gateways:
            row = {
                "kind": "app-gateway",
                "id": g.id,
                "name": g.name,
                "location": g.location,
                "subscription": subscription_id,
                "sku": g.sku.name if g.sku else None,
                "tier": g.sku.tier if g.sku else None,
                "waf_configuration": bool(g.web_application_firewall_configuration),
                "waf_mode": (g.web_application_firewall_configuration.firewall_mode if g.web_application_firewall_configuration else None),
                "http2": g.enable_http2,
                "ssl_policy_min": (g.ssl_policy.min_protocol_version if g.ssl_policy else None),
            }
            attach_identity(row, g)
            if focused:
                row["frontend_ip_configurations"] = [
                    {
                        "name": f.name,
                        "private_ip_address": f.private_ip_address,
                        "public_ip_id": f.public_ip_address.id if f.public_ip_address else None,
                    }
                    for f in g.frontend_ip_configurations or []
                ]
                row["http_listeners"] = [
                    {
                        "name": l.name,
                        "protocol": l.protocol,
                        "host_names": l.host_names or ([l.host_name] if l.host_name else []),
                        "ssl_certificate_id": l.ssl_certificate.id if l.ssl_certificate else None,
                    }
                    for l in g.http_listeners or []
                ]
                row["backend_address_pools"] = [
                    {
                        "name": p.name,
                        "addresses": [
                            a.fqdn or a.ip_address
                            for a in (p.backend_addresses or [])
                        ],
                    }
                    for p in g.backend_address_pools or []
                ]
            result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "gateway_count": len(gateways),
            "gateways_without_waf": sum(1 for g in gateways if not g.web_application_firewall_configuration),
        }
