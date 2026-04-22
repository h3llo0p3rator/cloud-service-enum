"""AWS Config recorders, delivery channels and conformance packs."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class ConfigService(AwsService):
    service_name = "config"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("config") as cfg:
            recorders = (await safe(cfg.describe_configuration_recorders())) or {}
            channels = (await safe(cfg.describe_delivery_channels())) or {}
            status = (await safe(cfg.describe_configuration_recorder_status())) or {}

        recorder_list = recorders.get("ConfigurationRecorders", []) or []
        statuses = {s["name"]: s for s in status.get("ConfigurationRecordersStatus", [])}

        for r in recorder_list:
            s = statuses.get(r["name"], {})
            result.resources.append(
                {
                    "kind": "recorder",
                    "id": r["name"],
                    "region": ctx.region,
                    "role_arn": r.get("roleARN"),
                    "all_supported": (r.get("recordingGroup") or {}).get("allSupported"),
                    "include_global": (r.get("recordingGroup") or {}).get("includeGlobalResourceTypes"),
                    "recording": s.get("recording"),
                    "last_status": s.get("lastStatus"),
                }
            )
        for c in channels.get("DeliveryChannels", []) or []:
            result.resources.append(
                {
                    "kind": "delivery-channel",
                    "id": c["name"],
                    "region": ctx.region,
                    "s3_bucket": c.get("s3BucketName"),
                    "s3_key_prefix": c.get("s3KeyPrefix"),
                    "sns_topic": c.get("snsTopicARN"),
                }
            )

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "recorder_count": len(recorder_list),
            "config_enabled": any(r.get("recording") for r in result.resources if r.get("kind") == "recorder"),
        }
