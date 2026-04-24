"""Elastic Beanstalk — applications, versions and per-env option settings.

EB environments expose application env vars via the
``aws:elasticbeanstalk:application:environment`` option namespace.
Promoting those into an ``env_vars`` block lets the existing env-var
renderer + secret scanner fire unchanged.
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

_ENV_NAMESPACE = "aws:elasticbeanstalk:application:environment"


class ElasticBeanstalkService(AwsService):
    service_name = "elasticbeanstalk"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        secret_scan = ctx.scope.secret_scan
        async with ctx.client("elasticbeanstalk") as eb:
            apps_resp = await safe(eb.describe_applications())
            applications = (apps_resp or {}).get("Applications", []) or []
            for app in applications:
                result.resources.append(_app_row(app, ctx.region))

            if focused:
                versions = collect_items(
                    await paginate(eb, "describe_application_versions"),
                    "ApplicationVersions",
                )
                for ver in versions:
                    result.resources.append(_version_row(ver, ctx.region))

            envs_resp = await safe(eb.describe_environments())
            envs = (envs_resp or {}).get("Environments", []) or []
            for env in envs:
                env_name = env.get("EnvironmentName")
                app_name = env.get("ApplicationName")
                row = _env_row(env, ctx.region)
                if focused and env_name and app_name:
                    await _enrich_env(eb, app_name, env_name, row, secret_scan)
                result.resources.append(row)

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "application_count": len(applications),
            "environment_count": len(envs),
        }


def _app_row(app: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "kind": "eb-application",
        "id": app.get("ApplicationArn"),
        "arn": app.get("ApplicationArn"),
        "name": app.get("ApplicationName"),
        "region": region,
        "description": app.get("Description"),
        "versions": app.get("Versions") or [],
        "created_at": app.get("DateCreated"),
        "updated_at": app.get("DateUpdated"),
    }


def _version_row(ver: dict[str, Any], region: str) -> dict[str, Any]:
    bundle = ver.get("SourceBundle") or {}
    return {
        "kind": "eb-application-version",
        "id": ver.get("ApplicationVersionArn"),
        "arn": ver.get("ApplicationVersionArn"),
        "name": ver.get("VersionLabel"),
        "region": region,
        "application": ver.get("ApplicationName"),
        "status": ver.get("Status"),
        "source_bundle": {
            "bucket": bundle.get("S3Bucket"),
            "key": bundle.get("S3Key"),
        },
        "description": ver.get("Description"),
        "created_at": ver.get("DateCreated"),
        "updated_at": ver.get("DateUpdated"),
    }


def _env_row(env: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "kind": "eb-environment",
        "id": env.get("EnvironmentArn") or env.get("EnvironmentId"),
        "arn": env.get("EnvironmentArn"),
        "name": env.get("EnvironmentName"),
        "region": region,
        "application": env.get("ApplicationName"),
        "status": env.get("Status"),
        "health": env.get("Health"),
        "health_status": env.get("HealthStatus"),
        "cname": env.get("CNAME"),
        "endpoint_url": env.get("EndpointURL"),
        "platform_arn": env.get("PlatformArn"),
        "solution_stack_name": env.get("SolutionStackName"),
        "tier": (env.get("Tier") or {}).get("Name"),
        "version_label": env.get("VersionLabel"),
    }


async def _enrich_env(
    eb: Any,
    app_name: str,
    env_name: str,
    row: dict[str, Any],
    secret_scan: bool,
) -> None:
    resp = await safe(
        eb.describe_configuration_settings(
            ApplicationName=app_name, EnvironmentName=env_name
        )
    )
    settings = (resp or {}).get("ConfigurationSettings", []) or []
    if not settings:
        return
    options = settings[0].get("OptionSettings", []) or []
    env_vars: dict[str, str] = {}
    non_env_options: list[dict[str, Any]] = []
    for opt in options:
        ns = opt.get("Namespace")
        name = opt.get("OptionName")
        value = opt.get("Value")
        if ns == _ENV_NAMESPACE and name is not None:
            env_vars[name] = "" if value is None else str(value)
        elif value not in (None, ""):
            non_env_options.append(
                {
                    "namespace": ns,
                    "name": name,
                    "value": value,
                    "resource": opt.get("ResourceName"),
                }
            )
    if env_vars:
        row["env_vars"] = env_vars
        if secret_scan:
            hits = scan_mapping(env_name, env_vars)
            if hits:
                row["secrets_found"] = [h.as_dict() for h in hits]
    if non_env_options:
        row["option_settings"] = non_env_options
