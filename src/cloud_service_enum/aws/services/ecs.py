"""ECS — clusters, services, task definitions and running task endpoints.

Task definitions are the high-value target: the container environment
block routinely embeds plaintext secrets, and the ``secrets[]`` block
references Parameter Store / Secrets Manager ARNs that point directly at
cross-account credentials. Shallow mode returns cluster / service
metadata; focused mode pulls task definitions with env vars and resolves
running-task ENIs to private/public IPs via EC2.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import (
    AwsService,
    ServiceContext,
    collect_items,
    paginate,
    safe,
)
from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.core.secrets import scan_mapping

_DESCRIBE_CLUSTER_INCLUDE = ["SETTINGS", "ATTACHMENTS", "TAGS"]
_TASK_BATCH = 100
_RUNNING_TASK_CAP = 50


class EcsService(AwsService):
    service_name = "ecs"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        secret_scan = ctx.scope.secret_scan
        async with ctx.client("ecs") as ecs, ctx.client("ec2") as ec2:
            cluster_arns = [
                arn
                for page in await paginate(ecs, "list_clusters")
                for arn in page.get("clusterArns", []) or []
            ]
            clusters = await _describe_clusters(ecs, cluster_arns)
            for cluster in clusters:
                result.resources.append(_cluster_row(cluster, ctx.region))

            services_per_cluster = await _all_services(ecs, cluster_arns)
            for cluster_arn, services in services_per_cluster.items():
                for svc in services:
                    result.resources.append(
                        _service_row(svc, cluster_arn, ctx.region)
                    )

            if focused:
                task_def_arns = _collect_task_def_arns(services_per_cluster)
                for arn in task_def_arns:
                    td = await safe(ecs.describe_task_definition(taskDefinition=arn))
                    if td and td.get("taskDefinition"):
                        result.resources.append(
                            _task_def_row(td["taskDefinition"], ctx.region, secret_scan)
                        )
                running_rows = await _running_tasks(ecs, ec2, cluster_arns, ctx.region)
                result.resources.extend(running_rows)

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "cluster_count": len(clusters),
            "service_count": sum(len(s) for s in services_per_cluster.values()),
        }


async def _describe_clusters(ecs: Any, arns: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for chunk in _chunks(arns, _TASK_BATCH):
        resp = await safe(
            ecs.describe_clusters(clusters=chunk, include=_DESCRIBE_CLUSTER_INCLUDE)
        )
        out.extend((resp or {}).get("clusters", []) or [])
    return out


async def _all_services(
    ecs: Any, cluster_arns: list[str]
) -> dict[str, list[dict[str, Any]]]:
    """Return ``{cluster_arn: [service_dict]}`` — listed + described."""
    out: dict[str, list[dict[str, Any]]] = {}
    for cluster_arn in cluster_arns:
        svc_arns: list[str] = []
        pages = await safe(paginate(ecs, "list_services", cluster=cluster_arn))
        for page in pages or []:
            svc_arns.extend(page.get("serviceArns", []) or [])
        services: list[dict[str, Any]] = []
        for chunk in _chunks(svc_arns, 10):  # describe_services cap is 10
            resp = await safe(
                ecs.describe_services(cluster=cluster_arn, services=chunk)
            )
            services.extend((resp or {}).get("services", []) or [])
        out[cluster_arn] = services
    return out


def _cluster_row(cluster: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "kind": "ecs-cluster",
        "id": cluster.get("clusterArn"),
        "arn": cluster.get("clusterArn"),
        "name": cluster.get("clusterName"),
        "region": region,
        "status": cluster.get("status"),
        "active_services": cluster.get("activeServicesCount", 0),
        "running_tasks": cluster.get("runningTasksCount", 0),
        "pending_tasks": cluster.get("pendingTasksCount", 0),
        "registered_instances": cluster.get("registeredContainerInstancesCount", 0),
        "capacity_providers": cluster.get("capacityProviders") or [],
        "settings": {s.get("name"): s.get("value") for s in cluster.get("settings") or []},
        "tags": {t.get("key"): t.get("value") for t in cluster.get("tags") or []},
    }


def _service_row(
    service: dict[str, Any], cluster_arn: str, region: str
) -> dict[str, Any]:
    network = service.get("networkConfiguration") or {}
    awsvpc = network.get("awsvpcConfiguration") or {}
    return {
        "kind": "ecs-service",
        "id": service.get("serviceArn"),
        "arn": service.get("serviceArn"),
        "name": service.get("serviceName"),
        "region": region,
        "cluster": cluster_arn,
        "status": service.get("status"),
        "task_definition": service.get("taskDefinition"),
        "desired": service.get("desiredCount"),
        "running": service.get("runningCount"),
        "launch_type": service.get("launchType"),
        "role_arn": service.get("roleArn"),
        "subnets": awsvpc.get("subnets") or [],
        "security_groups": awsvpc.get("securityGroups") or [],
        "assign_public_ip": awsvpc.get("assignPublicIp"),
        "load_balancers": [
            {
                "target_group": lb.get("targetGroupArn"),
                "container": lb.get("containerName"),
                "port": lb.get("containerPort"),
            }
            for lb in service.get("loadBalancers") or []
        ],
    }


def _collect_task_def_arns(
    services_per_cluster: dict[str, list[dict[str, Any]]],
) -> list[str]:
    seen: set[str] = set()
    for services in services_per_cluster.values():
        for svc in services:
            arn = svc.get("taskDefinition")
            if arn:
                seen.add(arn)
    return sorted(seen)


def _task_def_row(
    td: dict[str, Any], region: str, secret_scan: bool
) -> dict[str, Any]:
    containers = td.get("containerDefinitions") or []
    merged_env: dict[str, str] = {}
    secrets_refs: list[dict[str, Any]] = []
    for c in containers:
        for env in c.get("environment") or []:
            if "name" in env:
                merged_env[f"{c.get('name', '?')}.{env['name']}"] = str(env.get("value", ""))
        for s in c.get("secrets") or []:
            secrets_refs.append(
                {
                    "container": c.get("name"),
                    "name": s.get("name"),
                    "value_from": s.get("valueFrom"),
                }
            )
    row: dict[str, Any] = {
        "kind": "ecs-task-def",
        "id": td.get("taskDefinitionArn"),
        "arn": td.get("taskDefinitionArn"),
        "name": td.get("family"),
        "region": region,
        "revision": td.get("revision"),
        "task_role": td.get("taskRoleArn"),
        "execution_role": td.get("executionRoleArn"),
        "network_mode": td.get("networkMode"),
        "cpu": td.get("cpu"),
        "memory": td.get("memory"),
        "compatibilities": td.get("compatibilities") or [],
        "container_count": len(containers),
        "container_images": [c.get("image") for c in containers],
    }
    if merged_env:
        row["env_vars"] = merged_env
        if secret_scan:
            hits = scan_mapping(td.get("family") or "taskdef", merged_env)
            if hits:
                row["secrets_found"] = [h.as_dict() for h in hits]
    if secrets_refs:
        row["secrets"] = secrets_refs
    return row


async def _running_tasks(
    ecs: Any, ec2: Any, cluster_arns: list[str], region: str
) -> list[dict[str, Any]]:
    """Resolve running-task ENIs to private/public IPs via EC2.

    Attacker-relevant because public IPs on running tasks are your
    shortest path from a task-definition env-var leak to an active
    endpoint.
    """
    out: list[dict[str, Any]] = []
    for cluster_arn in cluster_arns:
        task_arns: list[str] = []
        pages = await safe(
            paginate(ecs, "list_tasks", cluster=cluster_arn, desiredStatus="RUNNING")
        )
        for page in pages or []:
            task_arns.extend(page.get("taskArns", []) or [])
        if not task_arns:
            continue
        task_arns = task_arns[:_RUNNING_TASK_CAP]
        for chunk in _chunks(task_arns, 100):  # describe_tasks cap is 100
            resp = await safe(ecs.describe_tasks(cluster=cluster_arn, tasks=chunk))
            tasks = (resp or {}).get("tasks", []) or []
            eni_ids = _eni_ids_from_tasks(tasks)
            eni_lookup = await _resolve_enis(ec2, eni_ids) if eni_ids else {}
            for task in tasks:
                out.append(_task_row(task, eni_lookup, region))
    return out


def _eni_ids_from_tasks(tasks: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for task in tasks:
        for att in task.get("attachments") or []:
            for detail in att.get("details") or []:
                if detail.get("name") == "networkInterfaceId" and detail.get("value"):
                    ids.append(detail["value"])
    return ids


async def _resolve_enis(ec2: Any, eni_ids: list[str]) -> dict[str, dict[str, Any]]:
    resp = await safe(ec2.describe_network_interfaces(NetworkInterfaceIds=eni_ids))
    out: dict[str, dict[str, Any]] = {}
    for eni in (resp or {}).get("NetworkInterfaces", []) or []:
        out[eni.get("NetworkInterfaceId", "")] = {
            "private_ip": eni.get("PrivateIpAddress"),
            "public_ip": (eni.get("Association") or {}).get("PublicIp"),
            "subnet_id": eni.get("SubnetId"),
            "vpc_id": eni.get("VpcId"),
        }
    return out


def _task_row(
    task: dict[str, Any], eni_lookup: dict[str, dict[str, Any]], region: str
) -> dict[str, Any]:
    eni_id = ""
    for att in task.get("attachments") or []:
        for detail in att.get("details") or []:
            if detail.get("name") == "networkInterfaceId":
                eni_id = detail.get("value") or ""
    eni = eni_lookup.get(eni_id, {})
    return {
        "kind": "ecs-task",
        "id": task.get("taskArn"),
        "arn": task.get("taskArn"),
        "region": region,
        "cluster": task.get("clusterArn"),
        "task_definition": task.get("taskDefinitionArn"),
        "last_status": task.get("lastStatus"),
        "desired_status": task.get("desiredStatus"),
        "launch_type": task.get("launchType"),
        "eni": eni_id,
        "private_ip": eni.get("private_ip"),
        "public_ip": eni.get("public_ip"),
        "subnet_id": eni.get("subnet_id"),
        "vpc_id": eni.get("vpc_id"),
        "started_at": task.get("startedAt"),
    }


def _chunks(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]
