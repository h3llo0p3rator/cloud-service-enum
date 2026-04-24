"""RDS instances, clusters and snapshots."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class RdsService(AwsService):
    service_name = "rds"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        # Every RDS call must stay inside this ``async with`` so aioboto3
        # can close the underlying aiohttp session cleanly. Previously
        # the snapshot-attribute fetch ran after the block closed, which
        # is what produced the "Unclosed client session" warning.
        async with ctx.client("rds") as rds:
            instances = collect_items(await paginate(rds, "describe_db_instances"), "DBInstances")
            clusters = collect_items(await paginate(rds, "describe_db_clusters"), "DBClusters")
            snapshots = collect_items(await paginate(rds, "describe_db_snapshots"), "DBSnapshots")
            proxies: list[dict[str, Any]] = []
            if focused:
                proxy_pages = await safe(paginate(rds, "describe_db_proxies"))
                if proxy_pages:
                    proxies = collect_items(proxy_pages, "DBProxies")
            snapshot_attrs: dict[str, list[dict[str, Any]]] = {}
            if focused:
                for s in snapshots:
                    snap_id = s["DBSnapshotIdentifier"]
                    attr_resp = await safe(
                        rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap_id)
                    )
                    attrs = (
                        ((attr_resp or {}).get("DBSnapshotAttributesResult") or {})
                        .get("DBSnapshotAttributes")
                        or []
                    )
                    if attrs:
                        snapshot_attrs[snap_id] = attrs

        for db in instances:
            result.resources.append(
                {
                    "kind": "db-instance",
                    "id": db["DBInstanceIdentifier"],
                    "region": ctx.region,
                    "engine": db.get("Engine"),
                    "status": db.get("DBInstanceStatus"),
                    "publicly_accessible": db.get("PubliclyAccessible", False),
                    "storage_encrypted": db.get("StorageEncrypted", False),
                    "kms_key_id": db.get("KmsKeyId"),
                    "backup_retention": db.get("BackupRetentionPeriod"),
                    "multi_az": db.get("MultiAZ"),
                    "deletion_protection": db.get("DeletionProtection", False),
                    "iam_db_auth": db.get("IAMDatabaseAuthenticationEnabled", False),
                    "auto_minor_version": db.get("AutoMinorVersionUpgrade", False),
                    "endpoint": db.get("Endpoint", {}).get("Address"),
                    "master_username": db.get("MasterUsername"),
                    "vpc_security_groups": [
                        g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])
                    ],
                }
            )
        for c in clusters:
            result.resources.append(
                {
                    "kind": "db-cluster",
                    "id": c["DBClusterIdentifier"],
                    "region": ctx.region,
                    "engine": c.get("Engine"),
                    "storage_encrypted": c.get("StorageEncrypted", False),
                    "kms_key_id": c.get("KmsKeyId"),
                    "backup_retention": c.get("BackupRetentionPeriod"),
                    "deletion_protection": c.get("DeletionProtection", False),
                    "iam_db_auth": c.get("IAMDatabaseAuthenticationEnabled", False),
                    "endpoint": c.get("Endpoint"),
                    "master_username": c.get("MasterUsername"),
                }
            )
        for s in snapshots:
            snap_id = s["DBSnapshotIdentifier"]
            row: dict[str, Any] = {
                "kind": "db-snapshot",
                "id": snap_id,
                "region": ctx.region,
                "encrypted": s.get("Encrypted", False),
                "engine": s.get("Engine"),
            }
            attrs = snapshot_attrs.get(snap_id) or []
            if attrs:
                row["shared_with"] = [
                    {"attribute": a.get("AttributeName"), "values": a.get("AttributeValues")}
                    for a in attrs
                    if a.get("AttributeValues")
                ]
            result.resources.append(row)
        for p in proxies:
            result.resources.append(
                {
                    "kind": "db-proxy",
                    "id": p.get("DBProxyName"),
                    "arn": p.get("DBProxyArn"),
                    "region": ctx.region,
                    "engine_family": p.get("EngineFamily"),
                    "endpoint": p.get("Endpoint"),
                    "auth": p.get("Auth"),
                    "require_tls": p.get("RequireTLS"),
                    "vpc_security_groups": p.get("VpcSecurityGroupIds"),
                }
            )

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "db_count": len(instances),
            "public_dbs": sum(1 for d in instances if d.get("PubliclyAccessible")),
            "unencrypted_dbs": sum(1 for d in instances if not d.get("StorageEncrypted")),
            "cluster_count": len(clusters),
        }
