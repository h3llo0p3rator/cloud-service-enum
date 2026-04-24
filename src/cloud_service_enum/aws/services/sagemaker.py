"""SageMaker — notebooks, lifecycle scripts, endpoints, models, jobs, pipelines.

Lifecycle configuration scripts are base64 shell blobs that run as
``root`` on notebook boot, which makes them the single most attacker-
relevant surface in the whole service — they are decoded and surfaced
via ``script`` so the existing code-panel renderer picks them up.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.core.secrets import scan_mapping

_LIST_LIMIT = 50


class SageMakerService(AwsService):
    service_name = "sagemaker"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        secret_scan = ctx.scope.secret_scan
        async with ctx.client("sagemaker") as sm:
            notebooks = await _page(sm, "list_notebook_instances", "NotebookInstances")
            for nb in notebooks:
                result.resources.append(
                    await _notebook_row(sm, nb, ctx.region, focused)
                )

            endpoints = await _page(sm, "list_endpoints", "Endpoints")
            for ep in endpoints:
                result.resources.append(
                    await _endpoint_row(sm, ep, ctx.region, focused)
                )

            models = await _page(sm, "list_models", "Models")
            for model in models:
                result.resources.append(
                    await _model_row(sm, model, ctx.region, focused, secret_scan)
                )

            if focused:
                training = await _page(
                    sm,
                    "list_training_jobs",
                    "TrainingJobSummaries",
                    MaxResults=_LIST_LIMIT,
                    SortBy="CreationTime",
                    SortOrder="Descending",
                )
                for job in training:
                    result.resources.append(
                        await _training_row(sm, job, ctx.region, secret_scan)
                    )

                processing = await _page(
                    sm,
                    "list_processing_jobs",
                    "ProcessingJobSummaries",
                    MaxResults=_LIST_LIMIT,
                    SortBy="CreationTime",
                    SortOrder="Descending",
                )
                for job in processing:
                    result.resources.append(
                        await _processing_row(sm, job, ctx.region, secret_scan)
                    )

                pipelines = await _page(sm, "list_pipelines", "PipelineSummaries")
                for pipeline in pipelines:
                    result.resources.append(
                        await _pipeline_row(sm, pipeline, ctx.region)
                    )

                domains = await _page(sm, "list_domains", "Domains")
                for domain in domains:
                    result.resources.append(
                        await _domain_row(sm, domain, ctx.region)
                    )

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "notebook_count": len(notebooks),
            "endpoint_count": len(endpoints),
            "model_count": len(models),
        }


async def _page(
    client: Any, op: str, key: str, **kwargs: Any
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["NextToken"] = next_token
        resp = await safe(getattr(client, op)(**call_kwargs))
        if not resp:
            break
        items.extend(resp.get(key, []) or [])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


async def _notebook_row(
    sm: Any, nb: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    name = nb.get("NotebookInstanceName")
    row: dict[str, Any] = {
        "kind": "sagemaker-notebook",
        "id": nb.get("NotebookInstanceArn") or name,
        "arn": nb.get("NotebookInstanceArn"),
        "name": name,
        "region": region,
        "status": nb.get("NotebookInstanceStatus"),
        "instance_type": nb.get("InstanceType"),
        "url": nb.get("Url"),
    }
    if not focused or not name:
        return row
    detail = await safe(sm.describe_notebook_instance(NotebookInstanceName=name))
    if not detail:
        return row
    row["role_arn"] = detail.get("RoleArn")
    row["direct_internet_access"] = detail.get("DirectInternetAccess")
    row["volume_size_gb"] = detail.get("VolumeSizeInGB")
    row["subnet_id"] = detail.get("SubnetId")
    row["security_groups"] = detail.get("SecurityGroups") or []
    row["kms_key_id"] = detail.get("KmsKeyId")
    row["root_access"] = detail.get("RootAccess")
    row["default_code_repository"] = detail.get("DefaultCodeRepository")
    lifecycle_name = detail.get("NotebookInstanceLifecycleConfigName")
    if lifecycle_name:
        row["lifecycle_config_name"] = lifecycle_name
        await _attach_lifecycle_script(sm, lifecycle_name, row)
    return row


async def _attach_lifecycle_script(
    sm: Any, lifecycle_name: str, row: dict[str, Any]
) -> None:
    lc = await safe(
        sm.describe_notebook_instance_lifecycle_config(
            NotebookInstanceLifecycleConfigName=lifecycle_name
        )
    )
    if not lc:
        return
    pieces: list[str] = []
    for phase_key in ("OnCreate", "OnStart"):
        for entry in lc.get(phase_key) or []:
            content = entry.get("Content")
            if not content:
                continue
            decoded = _b64_decode(content)
            if decoded:
                pieces.append(f"# {phase_key}\n{decoded}")
    if pieces:
        row["script"] = "\n\n".join(pieces)
        row["script_language"] = "bash"


def _b64_decode(content: str) -> str | None:
    try:
        return base64.b64decode(content).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return None


async def _endpoint_row(
    sm: Any, ep: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    name = ep.get("EndpointName")
    row: dict[str, Any] = {
        "kind": "sagemaker-endpoint",
        "id": ep.get("EndpointArn") or name,
        "arn": ep.get("EndpointArn"),
        "name": name,
        "region": region,
        "status": ep.get("EndpointStatus"),
        "created_at": ep.get("CreationTime"),
    }
    if not focused or not name:
        return row
    detail = await safe(sm.describe_endpoint(EndpointName=name))
    if not detail:
        return row
    config_name = detail.get("EndpointConfigName")
    row["endpoint_config_name"] = config_name
    if config_name:
        cfg = await safe(sm.describe_endpoint_config(EndpointConfigName=config_name))
        if cfg:
            row["kms_key_id"] = cfg.get("KmsKeyId")
            row["production_variants"] = [
                {
                    "variant_name": v.get("VariantName"),
                    "model_name": v.get("ModelName"),
                    "initial_instance_count": v.get("InitialInstanceCount"),
                    "instance_type": v.get("InstanceType"),
                }
                for v in cfg.get("ProductionVariants") or []
            ]
    return row


async def _model_row(
    sm: Any,
    model: dict[str, Any],
    region: str,
    focused: bool,
    secret_scan: bool,
) -> dict[str, Any]:
    name = model.get("ModelName")
    row: dict[str, Any] = {
        "kind": "sagemaker-model",
        "id": model.get("ModelArn") or name,
        "arn": model.get("ModelArn"),
        "name": name,
        "region": region,
        "created_at": model.get("CreationTime"),
    }
    if not focused or not name:
        return row
    detail = await safe(sm.describe_model(ModelName=name))
    if not detail:
        return row
    row["execution_role"] = detail.get("ExecutionRoleArn")
    primary = detail.get("PrimaryContainer") or {}
    row["container_image"] = primary.get("Image")
    row["model_data"] = primary.get("ModelDataUrl")
    env = primary.get("Environment") or {}
    if env:
        row["env_vars"] = env
        if secret_scan:
            hits = scan_mapping(name or "model", env)
            if hits:
                row["secrets_found"] = [h.as_dict() for h in hits]
    return row


async def _training_row(
    sm: Any, job: dict[str, Any], region: str, secret_scan: bool
) -> dict[str, Any]:
    name = job.get("TrainingJobName")
    row: dict[str, Any] = {
        "kind": "sagemaker-training-job",
        "id": job.get("TrainingJobArn") or name,
        "arn": job.get("TrainingJobArn"),
        "name": name,
        "region": region,
        "status": job.get("TrainingJobStatus"),
        "created_at": job.get("CreationTime"),
    }
    if not name:
        return row
    detail = await safe(sm.describe_training_job(TrainingJobName=name))
    if not detail:
        return row
    row["role_arn"] = detail.get("RoleArn")
    row["output_s3"] = (detail.get("OutputDataConfig") or {}).get("S3OutputPath")
    row["input_s3"] = [
        (ch.get("DataSource") or {}).get("S3DataSource", {}).get("S3Uri")
        for ch in detail.get("InputDataConfig") or []
    ]
    env = detail.get("Environment") or {}
    if env:
        row["env_vars"] = env
        if secret_scan:
            hits = scan_mapping(name, env)
            if hits:
                row["secrets_found"] = [h.as_dict() for h in hits]
    return row


async def _processing_row(
    sm: Any, job: dict[str, Any], region: str, secret_scan: bool
) -> dict[str, Any]:
    name = job.get("ProcessingJobName")
    row: dict[str, Any] = {
        "kind": "sagemaker-processing-job",
        "id": job.get("ProcessingJobArn") or name,
        "arn": job.get("ProcessingJobArn"),
        "name": name,
        "region": region,
        "status": job.get("ProcessingJobStatus"),
        "created_at": job.get("CreationTime"),
    }
    if not name:
        return row
    detail = await safe(sm.describe_processing_job(ProcessingJobName=name))
    if not detail:
        return row
    row["role_arn"] = detail.get("RoleArn")
    env = detail.get("Environment") or {}
    if env:
        row["env_vars"] = env
        if secret_scan:
            hits = scan_mapping(name, env)
            if hits:
                row["secrets_found"] = [h.as_dict() for h in hits]
    return row


async def _pipeline_row(
    sm: Any, pipeline: dict[str, Any], region: str
) -> dict[str, Any]:
    name = pipeline.get("PipelineName")
    row: dict[str, Any] = {
        "kind": "sagemaker-pipeline",
        "id": pipeline.get("PipelineArn") or name,
        "arn": pipeline.get("PipelineArn"),
        "name": name,
        "region": region,
        "status": pipeline.get("PipelineStatus"),
    }
    if not name:
        return row
    detail = await safe(sm.describe_pipeline(PipelineName=name))
    if not detail:
        return row
    row["role_arn"] = detail.get("RoleArn")
    body = detail.get("PipelineDefinition")
    if isinstance(body, str) and body:
        try:
            row["definition"] = json.loads(body)
            row["definition_language"] = "json"
        except ValueError:
            row["definition"] = body
            row["definition_language"] = "text"
    return row


async def _domain_row(
    sm: Any, domain: dict[str, Any], region: str
) -> dict[str, Any]:
    domain_id = domain.get("DomainId")
    row: dict[str, Any] = {
        "kind": "sagemaker-studio-domain",
        "id": domain_id,
        "arn": domain.get("DomainArn"),
        "name": domain.get("DomainName"),
        "region": region,
        "status": domain.get("Status"),
    }
    if not domain_id:
        return row
    detail = await safe(sm.describe_domain(DomainId=domain_id))
    if detail:
        row["vpc_id"] = detail.get("VpcId")
        row["subnet_ids"] = detail.get("SubnetIds") or []
        row["auth_mode"] = detail.get("AuthMode")
        row["default_user_role"] = (
            detail.get("DefaultUserSettings") or {}
        ).get("ExecutionRole")
        row["url"] = detail.get("Url")
    profiles = await _page(
        sm, "list_user_profiles", "UserProfiles", DomainIdEquals=domain_id
    )
    if profiles:
        row["user_profiles"] = [
            {
                "name": p.get("UserProfileName"),
                "status": p.get("Status"),
                "last_modified": p.get("LastModifiedTime"),
            }
            for p in profiles
        ]
    apps = await _page(sm, "list_apps", "Apps", DomainIdEquals=domain_id)
    if apps:
        row["apps"] = [
            {
                "name": a.get("AppName"),
                "type": a.get("AppType"),
                "user_profile": a.get("UserProfileName"),
                "status": a.get("Status"),
            }
            for a in apps
        ]
    return row
