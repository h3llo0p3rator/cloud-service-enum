"""ElastiCache clusters and replication groups."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class ElastiCacheService(AwsService):
    service_name = "elasticache"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("elasticache") as ec:
            clusters = collect_items(
                await paginate(ec, "describe_cache_clusters"), "CacheClusters"
            )
            groups = collect_items(
                await paginate(ec, "describe_replication_groups"), "ReplicationGroups"
            )
            users = collect_items(
                (await safe(paginate(ec, "describe_users"))) or [], "Users"
            )
            user_groups = collect_items(
                (await safe(paginate(ec, "describe_user_groups"))) or [], "UserGroups"
            )
            subnet_groups = collect_items(
                (await safe(paginate(ec, "describe_cache_subnet_groups"))) or [],
                "CacheSubnetGroups",
            )
            snapshots = collect_items(
                (await safe(paginate(ec, "describe_snapshots"))) or [], "Snapshots"
            )
        for c in clusters:
            result.resources.append(
                {
                    "kind": "cache-cluster",
                    "id": c["CacheClusterId"],
                    "region": ctx.region,
                    "engine": c.get("Engine"),
                    "version": c.get("EngineVersion"),
                    "node_type": c.get("CacheNodeType"),
                    "status": c.get("CacheClusterStatus"),
                    "at_rest_encryption": c.get("AtRestEncryptionEnabled", False),
                    "transit_encryption": c.get("TransitEncryptionEnabled", False),
                    "auth_token_enabled": c.get("AuthTokenEnabled", False),
                }
            )
        for g in groups:
            result.resources.append(
                {
                    "kind": "replication-group",
                    "id": g["ReplicationGroupId"],
                    "region": ctx.region,
                    "at_rest_encryption": g.get("AtRestEncryptionEnabled", False),
                    "transit_encryption": g.get("TransitEncryptionEnabled", False),
                    "auth_token_enabled": g.get("AuthTokenEnabled", False),
                    "multi_az": g.get("MultiAZ"),
                    "automatic_failover": g.get("AutomaticFailover"),
                }
            )
        for u in users:
            result.resources.append(
                {
                    "kind": "user",
                    "id": u.get("UserId"),
                    "name": u.get("UserName"),
                    "region": ctx.region,
                    "engine": u.get("Engine"),
                    "auth_mode": (u.get("Authentication") or {}).get("Type"),
                    "access_string": u.get("AccessString"),
                }
            )
        for g in user_groups:
            result.resources.append(
                {
                    "kind": "user-group",
                    "id": g.get("UserGroupId"),
                    "region": ctx.region,
                    "engine": g.get("Engine"),
                    "user_ids": g.get("UserIds"),
                    "status": g.get("Status"),
                }
            )
        for sg in subnet_groups:
            result.resources.append(
                {
                    "kind": "subnet-group",
                    "id": sg.get("CacheSubnetGroupName"),
                    "region": ctx.region,
                    "vpc": sg.get("VpcId"),
                    "subnets": [s.get("SubnetIdentifier") for s in sg.get("Subnets") or []],
                }
            )
        for sn in snapshots:
            result.resources.append(
                {
                    "kind": "snapshot",
                    "id": sn.get("SnapshotName"),
                    "region": ctx.region,
                    "source": sn.get("CacheClusterId") or sn.get("ReplicationGroupId"),
                    "engine": sn.get("Engine"),
                    "status": sn.get("SnapshotStatus"),
                }
            )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "cluster_count": len(clusters),
            "replication_group_count": len(groups),
            "clusters_without_transit_encryption": sum(
                1 for c in clusters if not c.get("TransitEncryptionEnabled")
            ),
        }
