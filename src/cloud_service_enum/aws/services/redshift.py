"""Redshift clusters and serverless workgroups."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class RedshiftService(AwsService):
    service_name = "redshift"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("redshift") as rs:
            clusters = collect_items(await paginate(rs, "describe_clusters"), "Clusters")
        async with ctx.client("redshift-serverless") as rss:
            wg_resp = await safe(rss.list_workgroups())
        for c in clusters:
            result.resources.append(
                {
                    "kind": "cluster",
                    "id": c["ClusterIdentifier"],
                    "region": ctx.region,
                    "db_name": c.get("DBName"),
                    "node_type": c.get("NodeType"),
                    "status": c.get("ClusterStatus"),
                    "encrypted": c.get("Encrypted", False),
                    "kms_key_id": c.get("KmsKeyId"),
                    "publicly_accessible": c.get("PubliclyAccessible", False),
                    "iam_roles": [r["IamRoleArn"] for r in c.get("IamRoles", [])],
                    "vpc_id": c.get("VpcId"),
                    "enhanced_vpc_routing": c.get("EnhancedVpcRouting", False),
                    "logging_enabled": (c.get("LoggingStatus") or {}).get("LoggingEnabled", False),
                }
            )
        for wg in (wg_resp or {}).get("workgroups", []):
            result.resources.append(
                {
                    "kind": "workgroup",
                    "id": wg.get("workgroupArn"),
                    "name": wg.get("workgroupName"),
                    "region": ctx.region,
                    "namespace": wg.get("namespaceName"),
                    "status": wg.get("status"),
                    "publicly_accessible": wg.get("publiclyAccessible", False),
                }
            )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "cluster_count": len(clusters),
            "public_clusters": sum(1 for c in clusters if c.get("PubliclyAccessible")),
            "unencrypted_clusters": sum(1 for c in clusters if not c.get("Encrypted")),
        }
