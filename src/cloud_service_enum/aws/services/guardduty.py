"""GuardDuty detectors."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class GuardDutyService(AwsService):
    service_name = "guardduty"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("guardduty") as gd:
            resp = (await safe(gd.list_detectors())) or {}
            for did in resp.get("DetectorIds", []):
                d = (await safe(gd.get_detector(DetectorId=did))) or {}
                result.resources.append(
                    {
                        "kind": "detector",
                        "id": did,
                        "region": ctx.region,
                        "status": d.get("Status"),
                        "finding_publishing_frequency": d.get("FindingPublishingFrequency"),
                        "data_sources": d.get("DataSources"),
                        "features": d.get("Features"),
                    }
                )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "detector_count": len(resp.get("DetectorIds", [])),
            "guardduty_enabled": bool(resp.get("DetectorIds")),
        }
