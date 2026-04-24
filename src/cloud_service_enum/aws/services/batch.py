"""AWS Batch — compute environments, job queues, job definitions and jobs.

Job definitions embed container env vars + ``secrets[]`` Parameter
Store / Secrets Manager refs, mirroring the ECS task-definition shape.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.core.secrets import scan_mapping

_PAGE = 100
_RUNNING_CAP = 25


class BatchService(AwsService):
    service_name = "batch"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        secret_scan = ctx.scope.secret_scan
        async with ctx.client("batch") as batch:
            envs = await _page(
                batch, "describe_compute_environments", "computeEnvironments"
            )
            for env in envs:
                result.resources.append(_compute_env_row(env, ctx.region))

            queues = await _page(batch, "describe_job_queues", "jobQueues")
            for q in queues:
                result.resources.append(_queue_row(q, ctx.region))

            job_defs = await _page(
                batch,
                "describe_job_definitions",
                "jobDefinitions",
                status="ACTIVE",
            )
            for jd in job_defs:
                result.resources.append(
                    _job_def_row(jd, ctx.region, secret_scan)
                )

            if focused:
                for q in queues:
                    q_arn = q.get("jobQueueArn")
                    if not q_arn:
                        continue
                    running = await _recent_jobs(batch, q_arn)
                    for job in running:
                        result.resources.append(_job_row(job, ctx.region))

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "compute_env_count": len(envs),
            "queue_count": len(queues),
            "job_def_count": len(job_defs),
        }


async def _page(
    client: Any, op: str, key: str, **kwargs: Any
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        call_kwargs = dict(kwargs)
        call_kwargs.setdefault("maxResults", _PAGE)
        if next_token:
            call_kwargs["nextToken"] = next_token
        resp = await safe(getattr(client, op)(**call_kwargs))
        if not resp:
            break
        items.extend(resp.get(key, []) or [])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


def _compute_env_row(env: dict[str, Any], region: str) -> dict[str, Any]:
    compute = env.get("computeResources") or {}
    return {
        "kind": "batch-compute-env",
        "id": env.get("computeEnvironmentArn") or env.get("computeEnvironmentName"),
        "arn": env.get("computeEnvironmentArn"),
        "name": env.get("computeEnvironmentName"),
        "region": region,
        "type": env.get("type"),
        "state": env.get("state"),
        "status": env.get("status"),
        "service_role": env.get("serviceRole"),
        "instance_role": compute.get("instanceRole"),
        "compute_type": compute.get("type"),
        "min_vcpus": compute.get("minvCpus"),
        "max_vcpus": compute.get("maxvCpus"),
        "desired_vcpus": compute.get("desiredvCpus"),
        "subnets": compute.get("subnets") or [],
        "security_groups": compute.get("securityGroupIds") or [],
        "instance_types": compute.get("instanceTypes") or [],
    }


def _queue_row(queue: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "kind": "batch-job-queue",
        "id": queue.get("jobQueueArn") or queue.get("jobQueueName"),
        "arn": queue.get("jobQueueArn"),
        "name": queue.get("jobQueueName"),
        "region": region,
        "priority": queue.get("priority"),
        "state": queue.get("state"),
        "status": queue.get("status"),
        "compute_envs": [
            o.get("computeEnvironment")
            for o in queue.get("computeEnvironmentOrder") or []
        ],
    }


def _job_def_row(
    jd: dict[str, Any], region: str, secret_scan: bool
) -> dict[str, Any]:
    container = jd.get("containerProperties") or {}
    env_vars: dict[str, str] = {
        e.get("name", ""): str(e.get("value", ""))
        for e in container.get("environment") or []
        if e.get("name")
    }
    secrets = [
        {"name": s.get("name"), "value_from": s.get("valueFrom")}
        for s in container.get("secrets") or []
    ]
    row: dict[str, Any] = {
        "kind": "batch-job-def",
        "id": jd.get("jobDefinitionArn") or jd.get("jobDefinitionName"),
        "arn": jd.get("jobDefinitionArn"),
        "name": jd.get("jobDefinitionName"),
        "region": region,
        "revision": jd.get("revision"),
        "type": jd.get("type"),
        "status": jd.get("status"),
        "platform_capabilities": jd.get("platformCapabilities") or [],
        "image": container.get("image"),
        "command": container.get("command") or [],
        "job_role": container.get("jobRoleArn"),
        "execution_role": container.get("executionRoleArn"),
        "vcpus": container.get("vcpus"),
        "memory": container.get("memory"),
        "privileged": container.get("privileged", False),
    }
    if env_vars:
        row["env_vars"] = env_vars
        if secret_scan:
            hits = scan_mapping(jd.get("jobDefinitionName") or "batch-jobdef", env_vars)
            if hits:
                row["secrets_found"] = [h.as_dict() for h in hits]
    if secrets:
        row["secrets"] = secrets
    return row


async def _recent_jobs(batch: Any, queue_arn: str) -> list[dict[str, Any]]:
    resp = await safe(
        batch.list_jobs(jobQueue=queue_arn, jobStatus="RUNNING", maxResults=_RUNNING_CAP)
    )
    return (resp or {}).get("jobSummaryList", []) or []


def _job_row(job: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "kind": "batch-job",
        "id": job.get("jobArn") or job.get("jobId"),
        "arn": job.get("jobArn"),
        "name": job.get("jobName"),
        "region": region,
        "status": job.get("status"),
        "job_definition": job.get("jobDefinition"),
        "created_at": job.get("createdAt"),
        "started_at": job.get("startedAt"),
    }
