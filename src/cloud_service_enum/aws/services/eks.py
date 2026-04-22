"""EKS clusters."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class EksService(AwsService):
    service_name = "eks"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("eks") as eks:
            resp = (await safe(eks.list_clusters(maxResults=100))) or {}
            for name in resp.get("clusters", []):
                desc = (await safe(eks.describe_cluster(name=name))) or {}
                c = desc.get("cluster") or {}
                logging = (c.get("logging") or {}).get("clusterLogging", [])
                row = {
                    "kind": "cluster",
                    "id": c.get("arn") or name,
                    "name": name,
                    "arn": c.get("arn"),
                    "region": ctx.region,
                    "status": c.get("status"),
                    "version": c.get("version"),
                    "endpoint": c.get("endpoint"),
                    "role_arn": c.get("roleArn"),
                    "public_access": (
                        (c.get("resourcesVpcConfig") or {}).get("endpointPublicAccess")
                    ),
                    "private_access": (
                        (c.get("resourcesVpcConfig") or {}).get("endpointPrivateAccess")
                    ),
                    "public_cidrs": (
                        (c.get("resourcesVpcConfig") or {}).get("publicAccessCidrs", [])
                    ),
                    "secrets_encryption": bool(c.get("encryptionConfig")),
                    "logging_enabled_types": [
                        t for entry in logging if entry.get("enabled") for t in entry.get("types", [])
                    ],
                    "platform_version": c.get("platformVersion"),
                }
                entries = await safe(eks.list_access_entries(clusterName=name))
                if entries:
                    row["access_entries"] = entries.get("accessEntries", [])
                np_resp = await safe(eks.list_nodegroups(clusterName=name))
                if np_resp:
                    pools = []
                    for np_name in np_resp.get("nodegroups", []) or []:
                        np_desc = await safe(
                            eks.describe_nodegroup(clusterName=name, nodegroupName=np_name)
                        )
                        ng = (np_desc or {}).get("nodegroup") or {}
                        pools.append(
                            {
                                "name": np_name,
                                "node_role": ng.get("nodeRole"),
                                "ami_type": ng.get("amiType"),
                                "remote_access": ng.get("remoteAccess"),
                                "instance_types": ng.get("instanceTypes"),
                            }
                        )
                    row["node_pools"] = pools
                fp_resp = await safe(eks.list_fargate_profiles(clusterName=name))
                if fp_resp:
                    row["fargate_profiles"] = fp_resp.get("fargateProfileNames", [])
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "cluster_count": len(resp.get("clusters", [])),
            "public_clusters": sum(
                1 for r in result.resources if r.get("kind") == "cluster" and r.get("public_access")
            ),
            "clusters_without_secrets_encryption": sum(
                1 for r in result.resources if r.get("kind") == "cluster" and not r.get("secrets_encryption")
            ),
        }
