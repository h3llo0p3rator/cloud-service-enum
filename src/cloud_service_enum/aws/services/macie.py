"""Amazon Macie v2 session status."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class MacieService(AwsService):
    service_name = "macie"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("macie2") as m:
            session = await safe(m.get_macie_session())
            findings_stats = await safe(m.get_finding_statistics(groupBy="severity.description"))

        s = session or {}
        if s:
            result.resources.append(
                {
                    "kind": "session",
                    "id": "macie",
                    "region": ctx.region,
                    "status": s.get("status"),
                    "finding_publishing_frequency": s.get("findingPublishingFrequency"),
                    "created_at": s.get("createdAt"),
                    "service_role": s.get("serviceRole"),
                }
            )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "enabled": s.get("status") == "ENABLED",
            "finding_severities": {
                rec.get("groupKey"): rec.get("count")
                for rec in (findings_stats or {}).get("countsByGroup", [])
            },
        }
