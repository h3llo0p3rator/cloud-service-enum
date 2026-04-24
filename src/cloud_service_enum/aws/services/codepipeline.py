"""CodePipeline — pipelines with every stage + action configuration.

Action configurations frequently reference Parameter Store /
SecretsManager values plus cross-account role ARNs; the raw
``configuration`` map is kept intact so the policy-document renderer
can expose any cross-account principals in artifact store KMS keys.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.core.secrets import scan_mapping

_EXECUTION_HISTORY = 10


class CodePipelineService(AwsService):
    service_name = "codepipeline"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        secret_scan = ctx.scope.secret_scan
        async with ctx.client("codepipeline") as cp:
            summaries = await _page(cp, "list_pipelines", "pipelines")
            for summary in summaries:
                pipeline_name = summary.get("name")
                if not pipeline_name:
                    continue
                row = await _pipeline_row(
                    cp, pipeline_name, ctx.region, secret_scan
                )
                result.resources.append(row)
                if focused:
                    executions = await _recent_executions(cp, pipeline_name)
                    for execution in executions:
                        result.resources.append(
                            _execution_row(execution, pipeline_name, ctx.region)
                        )

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "pipeline_count": len(summaries),
        }


async def _page(client: Any, op: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        call_kwargs = dict(kwargs)
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


async def _pipeline_row(
    cp: Any, name: str, region: str, secret_scan: bool
) -> dict[str, Any]:
    detail = await safe(cp.get_pipeline(name=name))
    body = (detail or {}).get("pipeline") or {}
    metadata = (detail or {}).get("metadata") or {}
    artifact_store = body.get("artifactStore") or {}
    stages_out: list[dict[str, Any]] = []
    config_map: dict[str, str] = {}
    for stage in body.get("stages") or []:
        stage_name = stage.get("name")
        actions_out: list[dict[str, Any]] = []
        for action in stage.get("actions") or []:
            type_id = action.get("actionTypeId") or {}
            configuration = action.get("configuration") or {}
            action_name = action.get("name")
            for key, value in configuration.items():
                if isinstance(value, str):
                    config_map[f"{stage_name}/{action_name}/{key}"] = value
            actions_out.append(
                {
                    "name": action_name,
                    "category": type_id.get("category"),
                    "provider": type_id.get("provider"),
                    "version": type_id.get("version"),
                    "role_arn": action.get("roleArn"),
                    "namespace": action.get("namespace"),
                    "region": action.get("region"),
                    "configuration": configuration,
                    "input_artifacts": [
                        a.get("name") for a in action.get("inputArtifacts") or []
                    ],
                    "output_artifacts": [
                        a.get("name") for a in action.get("outputArtifacts") or []
                    ],
                }
            )
        stages_out.append(
            {
                "name": stage_name,
                "actions": actions_out,
            }
        )

    row: dict[str, Any] = {
        "kind": "codepipeline",
        "id": metadata.get("pipelineArn") or name,
        "arn": metadata.get("pipelineArn"),
        "name": name,
        "region": region,
        "version": body.get("version"),
        "role_arn": body.get("roleArn"),
        "pipeline_type": body.get("pipelineType"),
        "artifact_store_type": artifact_store.get("type"),
        "artifact_store_location": artifact_store.get("location"),
        "artifact_store_encryption_key": (
            artifact_store.get("encryptionKey") or {}
        ).get("id"),
        "artifact_store_region": artifact_store.get("region"),
        "stages": stages_out,
        "variables": [
            {
                "name": v.get("name"),
                "default_value": v.get("defaultValue"),
                "description": v.get("description"),
            }
            for v in body.get("variables") or []
        ],
        "created_at": metadata.get("created"),
        "updated_at": metadata.get("updated"),
    }
    if config_map and secret_scan:
        hits = scan_mapping(name, config_map)
        if hits:
            row["secrets_found"] = [h.as_dict() for h in hits]
    return row


async def _recent_executions(cp: Any, name: str) -> list[dict[str, Any]]:
    resp = await safe(
        cp.list_pipeline_executions(pipelineName=name, maxResults=_EXECUTION_HISTORY)
    )
    return (resp or {}).get("pipelineExecutionSummaries", []) or []


def _execution_row(
    execution: dict[str, Any], pipeline_name: str, region: str
) -> dict[str, Any]:
    return {
        "kind": "codepipeline-execution",
        "id": execution.get("pipelineExecutionId"),
        "region": region,
        "pipeline": pipeline_name,
        "status": execution.get("status"),
        "last_update": execution.get("lastUpdateTime"),
        "start_time": execution.get("startTime"),
        "trigger_type": (execution.get("trigger") or {}).get("triggerType"),
        "trigger_detail": (execution.get("trigger") or {}).get("triggerDetail"),
    }
