"""Security Hub hub status and enabled standards."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class SecurityHubService(AwsService):
    service_name = "securityhub"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("securityhub") as sh:
            hub = await safe(sh.describe_hub())
            standards = await safe(sh.get_enabled_standards())
        hub_d = hub or {}
        if hub_d:
            result.resources.append(
                {
                    "kind": "hub",
                    "id": hub_d.get("HubArn"),
                    "region": ctx.region,
                    "subscribed_at": hub_d.get("SubscribedAt"),
                    "auto_enable_controls": hub_d.get("AutoEnableControls"),
                    "control_finding_generator": hub_d.get("ControlFindingGenerator"),
                }
            )
        for s in (standards or {}).get("StandardsSubscriptions", []):
            result.resources.append(
                {
                    "kind": "standard",
                    "id": s.get("StandardsSubscriptionArn"),
                    "region": ctx.region,
                    "standard_arn": s.get("StandardsArn"),
                    "status": s.get("StandardsStatus"),
                }
            )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "enabled": bool(hub_d),
            "standards_enabled": len((standards or {}).get("StandardsSubscriptions", [])),
        }
