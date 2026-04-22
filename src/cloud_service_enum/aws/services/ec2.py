"""EC2 instances, volumes, snapshots, AMIs and key pairs."""

from __future__ import annotations

from typing import Any

import base64

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class Ec2Service(AwsService):
    service_name = "ec2"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("ec2") as ec2:
            instances = await self._instances(ec2, ctx.region)
            volumes = await self._volumes(ec2, ctx.region)
            snapshots = await self._public_snapshots(ec2, ctx.region)
            amis = await self._public_amis(ec2, ctx.region)
            keypairs = await self._key_pairs(ec2, ctx.region)
            launch_templates: list[dict[str, Any]] = []
            if focused:
                for inst in instances:
                    inst["user_data"] = await _instance_user_data(ec2, inst["id"])
                launch_templates = await _launch_templates(ec2, ctx.region)

        result.resources.extend(
            instances + volumes + snapshots + amis + keypairs + launch_templates
        )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "instance_count": len(instances),
            "imdsv2_required": sum(1 for i in instances if i.get("imds_http_tokens") == "required"),
            "public_instances": sum(1 for i in instances if i.get("public_ip")),
            "volume_count": len(volumes),
            "unencrypted_volumes": sum(1 for v in volumes if not v.get("encrypted")),
            "public_snapshots": len(snapshots),
            "public_amis": len(amis),
        }

    async def _instances(self, ec2: Any, region: str) -> list[dict[str, Any]]:
        pages = await paginate(ec2, "describe_instances")
        out: list[dict[str, Any]] = []
        for page in pages:
            for reservation in page.get("Reservations", []) or []:
                for inst in reservation.get("Instances", []):
                    md = inst.get("MetadataOptions", {})
                    out.append(
                        {
                            "kind": "instance",
                            "id": inst["InstanceId"],
                            "region": region,
                            "state": inst.get("State", {}).get("Name"),
                            "type": inst.get("InstanceType"),
                            "public_ip": inst.get("PublicIpAddress"),
                            "private_ip": inst.get("PrivateIpAddress"),
                            "imds_http_tokens": md.get("HttpTokens"),
                            "imds_hop_limit": md.get("HttpPutResponseHopLimit"),
                            "iam_profile": inst.get("IamInstanceProfile", {}).get("Arn"),
                            "vpc_id": inst.get("VpcId"),
                            "subnet_id": inst.get("SubnetId"),
                            "security_groups": [g["GroupId"] for g in inst.get("SecurityGroups", [])],
                            "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                            "ebs_optimized": inst.get("EbsOptimized"),
                            "launch_time": inst.get("LaunchTime"),
                        }
                    )
        return out

    async def _volumes(self, ec2: Any, region: str) -> list[dict[str, Any]]:
        pages = await paginate(ec2, "describe_volumes")
        return [
            {
                "kind": "volume",
                "id": v["VolumeId"],
                "region": region,
                "size": v.get("Size"),
                "encrypted": v.get("Encrypted", False),
                "kms_key_id": v.get("KmsKeyId"),
                "state": v.get("State"),
                "type": v.get("VolumeType"),
            }
            for v in collect_items(pages, "Volumes")
        ]

    async def _public_snapshots(self, ec2: Any, region: str) -> list[dict[str, Any]]:
        try:
            resp = await ec2.describe_snapshots(
                OwnerIds=["self"], RestorableByUserIds=["all"], MaxResults=100
            )
        except Exception:  # noqa: BLE001
            return []
        return [{"kind": "public-snapshot", "id": s["SnapshotId"], "region": region} for s in resp.get("Snapshots", [])]

    async def _public_amis(self, ec2: Any, region: str) -> list[dict[str, Any]]:
        try:
            resp = await ec2.describe_images(
                Owners=["self"], Filters=[{"Name": "is-public", "Values": ["true"]}]
            )
        except Exception:  # noqa: BLE001
            return []
        return [
            {"kind": "public-ami", "id": i["ImageId"], "region": region, "name": i.get("Name")}
            for i in resp.get("Images", [])
        ]

    async def _key_pairs(self, ec2: Any, region: str) -> list[dict[str, Any]]:
        try:
            resp = await ec2.describe_key_pairs()
        except Exception:  # noqa: BLE001
            return []
        return [
            {"kind": "key-pair", "id": k["KeyPairId"], "name": k["KeyName"], "region": region}
            for k in resp.get("KeyPairs", [])
        ]


async def _instance_user_data(ec2: Any, instance_id: str) -> str | None:
    """Fetch and base64-decode the user-data attribute for one instance."""
    resp = await safe(
        ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="userData")
    )
    if not resp:
        return None
    encoded = (resp.get("UserData") or {}).get("Value")
    if not encoded:
        return None
    try:
        return base64.b64decode(encoded).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return encoded


async def _launch_templates(ec2: Any, region: str) -> list[dict[str, Any]]:
    """Surface launch-template user-data and IAM profile for cred-pivot analysis."""
    pages = await safe(paginate(ec2, "describe_launch_templates"))
    if not pages:
        return []
    out: list[dict[str, Any]] = []
    for tpl in collect_items(pages, "LaunchTemplates"):
        tpl_id = tpl["LaunchTemplateId"]
        ver = await safe(
            ec2.describe_launch_template_versions(
                LaunchTemplateId=tpl_id, Versions=["$Latest"]
            )
        )
        versions = (ver or {}).get("LaunchTemplateVersions") or []
        data = (versions[0] if versions else {}).get("LaunchTemplateData") or {}
        encoded = data.get("UserData")
        user_data = None
        if encoded:
            try:
                user_data = base64.b64decode(encoded).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                user_data = encoded
        out.append(
            {
                "kind": "launch-template",
                "id": tpl_id,
                "name": tpl.get("LaunchTemplateName"),
                "region": region,
                "default_version": tpl.get("DefaultVersionNumber"),
                "iam_profile": (data.get("IamInstanceProfile") or {}).get("Arn"),
                "image_id": data.get("ImageId"),
                "user_data": user_data,
                "script_language": "bash",
            }
        )
    return out
