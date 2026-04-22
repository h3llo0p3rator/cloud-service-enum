"""MSK (managed Kafka) clusters."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate
from cloud_service_enum.core.models import ServiceResult


class MskService(AwsService):
    service_name = "msk"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("kafka") as kafka:
            clusters = collect_items(
                await paginate(kafka, "list_clusters_v2"), "ClusterInfoList"
            )
        for c in clusters:
            enc = (c.get("Provisioned") or {}).get("EncryptionInfo") or c.get("EncryptionInfo") or {}
            client_auth = (c.get("Provisioned") or {}).get("ClientAuthentication") or {}
            result.resources.append(
                {
                    "kind": "cluster",
                    "id": c.get("ClusterArn"),
                    "arn": c.get("ClusterArn"),
                    "name": c.get("ClusterName"),
                    "region": ctx.region,
                    "state": c.get("State"),
                    "type": c.get("ClusterType"),
                    "encryption_in_transit": enc.get("EncryptionInTransit"),
                    "encryption_at_rest_kms": (enc.get("EncryptionAtRest") or {}).get("DataVolumeKMSKeyId"),
                    "client_auth": client_auth,
                }
            )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "cluster_count": len(clusters),
        }
