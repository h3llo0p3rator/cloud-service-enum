"""WAFv2 web ACLs (regional + CloudFront)."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class WafV2Service(AwsService):
    service_name = "wafv2"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("wafv2") as waf:
            for scope in ("REGIONAL", "CLOUDFRONT"):
                if scope == "CLOUDFRONT" and ctx.region != "us-east-1":
                    continue
                resp = (await safe(waf.list_web_acls(Scope=scope, Limit=100))) or {}
                for acl in resp.get("WebACLs", []):
                    row: dict[str, Any] = {
                        "kind": "web-acl",
                        "id": acl["Id"],
                        "arn": acl.get("ARN"),
                        "name": acl.get("Name"),
                        "scope": scope,
                        "region": ctx.region,
                        "description": acl.get("Description"),
                    }
                    if focused:
                        details = await safe(
                            waf.get_web_acl(
                                Name=acl["Name"], Scope=scope, Id=acl["Id"]
                            )
                        )
                        body = (details or {}).get("WebACL") or {}
                        if body:
                            row["default_action"] = body.get("DefaultAction")
                            row["rule_count"] = len(body.get("Rules", []) or [])
                            row["policy_document"] = {
                                "Rules": body.get("Rules", []),
                                "VisibilityConfig": body.get("VisibilityConfig"),
                            }
                        resources = await safe(
                            waf.list_resources_for_web_acl(
                                WebACLArn=acl.get("ARN"),
                                ResourceType="APPLICATION_LOAD_BALANCER",
                            )
                        ) if scope == "REGIONAL" else None
                        if resources:
                            row["protected_resources"] = resources.get(
                                "ResourceArns", []
                            )
                    result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "web_acl_count": sum(1 for r in result.resources if r.get("kind") == "web-acl"),
        }
