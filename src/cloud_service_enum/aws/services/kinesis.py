"""Kinesis data streams."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class KinesisService(AwsService):
    service_name = "kinesis"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        names: list[str] = []
        async with ctx.client("kinesis") as k:
            for page in await paginate(k, "list_streams"):
                names.extend(page.get("StreamNames", []))
            for n in names:
                d = (await safe(k.describe_stream_summary(StreamName=n))) or {}
                s = d.get("StreamDescriptionSummary") or {}
                result.resources.append(
                    {
                        "kind": "stream",
                        "id": s.get("StreamARN") or n,
                        "name": n,
                        "region": ctx.region,
                        "status": s.get("StreamStatus"),
                        "encryption": s.get("EncryptionType"),
                        "kms_key": s.get("KeyId"),
                        "retention_hours": s.get("RetentionPeriodHours"),
                        "open_shards": s.get("OpenShardCount"),
                        "mode": (s.get("StreamModeDetails") or {}).get("StreamMode"),
                    }
                )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "stream_count": len(names),
            "unencrypted_streams": sum(
                1
                for r in result.resources
                if r.get("kind") == "stream" and r.get("encryption") == "NONE"
            ),
        }
