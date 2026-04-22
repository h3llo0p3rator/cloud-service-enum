"""EFS file systems."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class EfsService(AwsService):
    service_name = "efs"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("efs") as efs:
            filesystems = collect_items(
                await paginate(efs, "describe_file_systems"), "FileSystems"
            )
            for fs in filesystems:
                fs_id = fs["FileSystemId"]
                row: dict = {
                    "kind": "file-system",
                    "id": fs_id,
                    "arn": fs.get("FileSystemArn"),
                    "region": ctx.region,
                    "encrypted": fs.get("Encrypted", False),
                    "kms_key_id": fs.get("KmsKeyId"),
                    "performance": fs.get("PerformanceMode"),
                    "throughput": fs.get("ThroughputMode"),
                    "life_cycle_state": fs.get("LifeCycleState"),
                    "size_bytes": (fs.get("SizeInBytes") or {}).get("Value"),
                }
                pol = await safe(efs.describe_file_system_policy(FileSystemId=fs_id))
                body = (pol or {}).get("Policy")
                if isinstance(body, str) and body:
                    try:
                        row["policy_document"] = __import__("json").loads(body)
                    except ValueError:
                        row["policy_document"] = {"_raw": body}
                mounts = await safe(efs.describe_mount_targets(FileSystemId=fs_id))
                if mounts:
                    row["mount_targets"] = [
                        {
                            "id": m.get("MountTargetId"),
                            "subnet": m.get("SubnetId"),
                            "ip": m.get("IpAddress"),
                            "az": m.get("AvailabilityZoneName"),
                            "state": m.get("LifeCycleState"),
                        }
                        for m in mounts.get("MountTargets") or []
                    ]
                aps = await safe(efs.describe_access_points(FileSystemId=fs_id))
                if aps:
                    row["access_points"] = [
                        {
                            "id": a.get("AccessPointId"),
                            "arn": a.get("AccessPointArn"),
                            "name": a.get("Name"),
                            "posix_user": a.get("PosixUser"),
                            "root_dir": (a.get("RootDirectory") or {}).get("Path"),
                        }
                        for a in aps.get("AccessPoints") or []
                    ]
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "fs_count": len(filesystems),
            "unencrypted_fs": sum(1 for f in filesystems if not f.get("Encrypted")),
        }
