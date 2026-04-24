"""CodeBuild — projects, env vars, recent builds, report groups.

``PLAINTEXT`` env vars in CodeBuild projects routinely carry deploy
credentials for *other* accounts; the shared secret scanner is pointed
directly at them. ``PARAMETER_STORE`` / ``SECRETS_MANAGER`` refs are
surfaced alongside so they show up as auditable pivots.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.core.secrets import scan_mapping

_BATCH = 50
_BUILD_HISTORY = 10


class CodeBuildService(AwsService):
    service_name = "codebuild"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        secret_scan = ctx.scope.secret_scan
        async with ctx.client("codebuild") as cb:
            project_names = await _page(cb, "list_projects", "projects")
            projects = await _describe_chunked(cb, project_names)
            for project in projects:
                result.resources.append(
                    _project_row(project, ctx.region, secret_scan)
                )
                if focused:
                    builds = await _recent_builds(cb, project.get("name") or "")
                    for build in builds:
                        result.resources.append(_build_row(build, ctx.region))

            report_group_arns = await _page(
                cb, "list_report_groups", "reportGroups"
            )
            report_groups = await _describe_report_groups(cb, report_group_arns)
            for group in report_groups:
                result.resources.append(_report_group_row(group, ctx.region))

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "project_count": len(projects),
            "report_group_count": len(report_groups),
        }


async def _page(client: Any, op: str, key: str, **kwargs: Any) -> list[Any]:
    items: list[Any] = []
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


async def _describe_chunked(cb: Any, names: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for start in range(0, len(names), _BATCH):
        chunk = names[start : start + _BATCH]
        resp = await safe(cb.batch_get_projects(names=chunk))
        out.extend((resp or {}).get("projects", []) or [])
    return out


async def _describe_report_groups(cb: Any, arns: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for start in range(0, len(arns), _BATCH):
        chunk = arns[start : start + _BATCH]
        resp = await safe(cb.batch_get_report_groups(reportGroupArns=chunk))
        out.extend((resp or {}).get("reportGroups", []) or [])
    return out


def _project_row(
    project: dict[str, Any], region: str, secret_scan: bool
) -> dict[str, Any]:
    env = project.get("environment") or {}
    source = project.get("source") or {}
    artifacts = project.get("artifacts") or {}
    cache = project.get("cache") or {}
    vpc = project.get("vpcConfig") or {}

    plaintext_env: dict[str, str] = {}
    parameter_store: list[dict[str, str]] = []
    secrets_manager: list[dict[str, str]] = []
    for var in env.get("environmentVariables") or []:
        name = var.get("name")
        value = var.get("value")
        kind = var.get("type", "PLAINTEXT")
        if not name:
            continue
        if kind == "PLAINTEXT":
            plaintext_env[name] = "" if value is None else str(value)
        elif kind == "PARAMETER_STORE":
            parameter_store.append({"name": name, "value_from": value})
        elif kind == "SECRETS_MANAGER":
            secrets_manager.append({"name": name, "value_from": value})

    row: dict[str, Any] = {
        "kind": "codebuild-project",
        "id": project.get("arn") or project.get("name"),
        "arn": project.get("arn"),
        "name": project.get("name"),
        "region": region,
        "description": project.get("description"),
        "service_role": project.get("serviceRole"),
        "source_type": source.get("type"),
        "source_location": source.get("location"),
        "source_auth": (source.get("auth") or {}).get("type"),
        "artifact_type": artifacts.get("type"),
        "artifact_location": artifacts.get("location"),
        "artifact_encryption_disabled": artifacts.get("encryptionDisabled", False),
        "environment_type": env.get("type"),
        "environment_image": env.get("image"),
        "compute_type": env.get("computeType"),
        "privileged_mode": env.get("privilegedMode", False),
        "cache_type": cache.get("type"),
        "cache_location": cache.get("location"),
        "vpc_id": vpc.get("vpcId"),
        "subnets": vpc.get("subnets") or [],
        "security_groups": vpc.get("securityGroupIds") or [],
        "encryption_key": project.get("encryptionKey"),
        "timeout_minutes": project.get("timeoutInMinutes"),
        "last_modified": project.get("lastModified"),
    }
    if plaintext_env:
        row["env_vars"] = plaintext_env
        if secret_scan:
            hits = scan_mapping(project.get("name") or "codebuild", plaintext_env)
            if hits:
                row["secrets_found"] = [h.as_dict() for h in hits]
    if parameter_store:
        row["parameter_store_refs"] = parameter_store
    if secrets_manager:
        row["secrets_manager_refs"] = secrets_manager
    return row


async def _recent_builds(cb: Any, project_name: str) -> list[dict[str, Any]]:
    resp = await safe(
        cb.list_builds_for_project(
            projectName=project_name, sortOrder="DESCENDING"
        )
    )
    build_ids = (resp or {}).get("ids", []) or []
    build_ids = build_ids[:_BUILD_HISTORY]
    if not build_ids:
        return []
    detail = await safe(cb.batch_get_builds(ids=build_ids))
    return (detail or {}).get("builds", []) or []


def _build_row(build: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "kind": "codebuild-build",
        "id": build.get("arn") or build.get("id"),
        "arn": build.get("arn"),
        "name": build.get("id"),
        "region": region,
        "project": build.get("projectName"),
        "status": build.get("buildStatus"),
        "initiator": build.get("initiator"),
        "source_version": build.get("sourceVersion"),
        "resolved_source_version": build.get("resolvedSourceVersion"),
        "start_time": build.get("startTime"),
        "end_time": build.get("endTime"),
    }


def _report_group_row(group: dict[str, Any], region: str) -> dict[str, Any]:
    export = group.get("exportConfig") or {}
    s3 = export.get("s3Destination") or {}
    return {
        "kind": "codebuild-report-group",
        "id": group.get("arn") or group.get("name"),
        "arn": group.get("arn"),
        "name": group.get("name"),
        "region": region,
        "type": group.get("type"),
        "status": group.get("status"),
        "export_type": export.get("exportConfigType"),
        "export_bucket": s3.get("bucket"),
        "export_path": s3.get("path"),
        "export_encryption_key": s3.get("encryptionKey"),
        "export_encryption_disabled": s3.get("encryptionDisabled", False),
    }
