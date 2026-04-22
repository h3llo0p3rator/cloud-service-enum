"""CloudTrail trails, event selectors and logging status."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class CloudTrailService(AwsService):
    service_name = "cloudtrail"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("cloudtrail") as ct:
            resp = await ct.describe_trails(includeShadowTrails=False)
            trails = resp.get("trailList", [])
            enriched = []
            for trail in trails:
                arn = trail.get("TrailARN") or trail["Name"]
                status = await safe(ct.get_trail_status(Name=arn))
                selectors = await safe(ct.get_event_selectors(TrailName=arn))
                insight = await safe(ct.get_insight_selectors(TrailName=arn))
                enriched.append((trail, status, selectors, insight))
        bucket_policies: dict[str, Any] = {}
        if focused:
            bucket_names = sorted(
                {t.get("S3BucketName") for t, *_ in enriched if t.get("S3BucketName")}
            )
            if bucket_names:
                async with ctx.client("s3") as s3:
                    for name in bucket_names:
                        pol = await safe(s3.get_bucket_policy(Bucket=name))
                        body = (pol or {}).get("Policy")
                        if isinstance(body, str) and body:
                            try:
                                bucket_policies[name] = __import__("json").loads(body)
                            except ValueError:
                                bucket_policies[name] = {"_raw": body}

        multi_region = 0
        log_validation = 0
        for trail, status, selectors, insight in enriched:
            if trail.get("IsMultiRegionTrail"):
                multi_region += 1
            if trail.get("LogFileValidationEnabled"):
                log_validation += 1
            row: dict[str, Any] = {
                "kind": "trail",
                "id": trail.get("TrailARN", trail["Name"]),
                "name": trail["Name"],
                "region": ctx.region,
                "home_region": trail.get("HomeRegion"),
                "s3_bucket": trail.get("S3BucketName"),
                "kms_key_id": trail.get("KmsKeyId"),
                "multi_region": trail.get("IsMultiRegionTrail", False),
                "log_file_validation": trail.get("LogFileValidationEnabled", False),
                "cloudwatch_log_group": trail.get("CloudWatchLogsLogGroupArn"),
                "is_logging": (status or {}).get("IsLogging", False),
                "event_selectors": (selectors or {}).get("EventSelectors", []),
                "insight_selectors": (insight or {}).get("InsightSelectors", []),
            }
            if focused and trail.get("S3BucketName") in bucket_policies:
                row["policy_document"] = bucket_policies[trail["S3BucketName"]]
            result.resources.append(row)

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "trail_count": len(trails),
            "multi_region_trails": multi_region,
            "trails_with_log_validation": log_validation,
        }
