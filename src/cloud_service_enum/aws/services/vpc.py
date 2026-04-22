"""VPCs, subnets, security groups, NACLs and flow logs."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate
from cloud_service_enum.core.models import ServiceResult


class VpcService(AwsService):
    service_name = "vpc"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("ec2") as ec2:
            vpcs = collect_items(await paginate(ec2, "describe_vpcs"), "Vpcs")
            subnets = collect_items(await paginate(ec2, "describe_subnets"), "Subnets")
            sgs = collect_items(await paginate(ec2, "describe_security_groups"), "SecurityGroups")
            nacls = collect_items(await paginate(ec2, "describe_network_acls"), "NetworkAcls")
            flow_logs = collect_items(await paginate(ec2, "describe_flow_logs"), "FlowLogs")

        vpcs_with_flow_logs = {fl["ResourceId"] for fl in flow_logs}

        for v in vpcs:
            result.resources.append(
                {
                    "kind": "vpc",
                    "id": v["VpcId"],
                    "region": ctx.region,
                    "cidr": v.get("CidrBlock"),
                    "is_default": v.get("IsDefault", False),
                    "flow_logs_enabled": v["VpcId"] in vpcs_with_flow_logs,
                }
            )
        for s in subnets:
            result.resources.append(
                {
                    "kind": "subnet",
                    "id": s["SubnetId"],
                    "region": ctx.region,
                    "vpc": s["VpcId"],
                    "cidr": s.get("CidrBlock"),
                    "az": s.get("AvailabilityZone"),
                    "public": s.get("MapPublicIpOnLaunch", False),
                }
            )
        for sg in sgs:
            result.resources.append(
                {
                    "kind": "security-group",
                    "id": sg["GroupId"],
                    "name": sg.get("GroupName"),
                    "region": ctx.region,
                    "vpc": sg.get("VpcId"),
                    "world_open": _has_world_open(sg),
                    "world_open_ports": _world_ports(sg),
                    "ingress_rules": len(sg.get("IpPermissions", [])),
                    "egress_rules": len(sg.get("IpPermissionsEgress", [])),
                }
            )
        for n in nacls:
            result.resources.append(
                {
                    "kind": "network-acl",
                    "id": n["NetworkAclId"],
                    "region": ctx.region,
                    "vpc": n.get("VpcId"),
                    "is_default": n.get("IsDefault", False),
                }
            )

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "vpc_count": len(vpcs),
            "default_vpcs": sum(1 for v in vpcs if v.get("IsDefault")),
            "sg_count": len(sgs),
            "sgs_open_to_world": sum(1 for sg in sgs if _has_world_open(sg)),
            "vpcs_without_flow_logs": [v["VpcId"] for v in vpcs if v["VpcId"] not in vpcs_with_flow_logs],
        }


def _has_world_open(sg: dict[str, Any]) -> bool:
    for rule in sg.get("IpPermissions", []) or []:
        if any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []) or []):
            return True
        if any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []) or []):
            return True
    return False


def _world_ports(sg: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rule in sg.get("IpPermissions", []) or []:
        world = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []) or []) or any(
            r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []) or []
        )
        if world:
            out.append(
                {
                    "protocol": rule.get("IpProtocol"),
                    "from": rule.get("FromPort"),
                    "to": rule.get("ToPort"),
                }
            )
    return out
