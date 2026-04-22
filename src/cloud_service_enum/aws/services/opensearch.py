"""OpenSearch Service domains."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class OpenSearchService(AwsService):
    service_name = "opensearch"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("opensearch") as os_:
            resp = (await safe(os_.list_domain_names())) or {}
            for d in resp.get("DomainNames", []):
                name = d["DomainName"]
                desc = (await safe(os_.describe_domain(DomainName=name))) or {}
                status = desc.get("DomainStatus") or {}
                row = {
                        "kind": "domain",
                        "id": status.get("ARN") or name,
                        "arn": status.get("ARN"),
                        "name": name,
                        "region": ctx.region,
                        "engine_version": status.get("EngineVersion"),
                        "endpoint": status.get("Endpoint"),
                        "encryption_at_rest": (
                            status.get("EncryptionAtRestOptions") or {}
                        ).get("Enabled", False),
                        "node_to_node_encryption": (
                            status.get("NodeToNodeEncryptionOptions") or {}
                        ).get("Enabled", False),
                        "enforce_https": (
                            status.get("DomainEndpointOptions") or {}
                        ).get("EnforceHTTPS", False),
                        "tls_security_policy": (
                            status.get("DomainEndpointOptions") or {}
                        ).get("TLSSecurityPolicy"),
                        "vpc": (status.get("VPCOptions") or {}).get("VPCId"),
                        "log_publishing": list((status.get("LogPublishingOptions") or {}).keys()),
                }
                if focused:
                    cfg = await safe(os_.describe_domain_config(DomainName=name))
                    config = (cfg or {}).get("DomainConfig") or {}
                    if config:
                        access = (config.get("AccessPolicies") or {}).get("Options") or ""
                        if isinstance(access, str) and access:
                            try:
                                row["policy_document"] = __import__("json").loads(access)
                            except ValueError:
                                row["policy_document"] = {"_raw": access}
                        row["advanced_security"] = (
                            (config.get("AdvancedSecurityOptions") or {}).get("Options")
                        )
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "domain_count": len(resp.get("DomainNames", [])),
            "domains_without_encryption": sum(
                1
                for r in result.resources
                if r.get("kind") == "domain" and not r.get("encryption_at_rest")
            ),
        }
