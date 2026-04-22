"""Secrets Manager — secret metadata and resource policies (no values)."""

from __future__ import annotations

import json

from cloud_service_enum.aws.base import (
    AwsService,
    ServiceContext,
    collect_items,
    paginate,
    safe,
)
from cloud_service_enum.core.models import ServiceResult


class SecretsManagerService(AwsService):
    service_name = "secretsmanager"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("secretsmanager") as sm:
            secrets = collect_items(await paginate(sm, "list_secrets"), "SecretList")
            for s in secrets:
                arn = s["ARN"]
                row: dict = {
                    "kind": "secret",
                    "id": arn,
                    "arn": arn,
                    "name": s.get("Name"),
                    "region": ctx.region,
                    "description": s.get("Description"),
                    "kms_key": s.get("KmsKeyId"),
                    "rotation_enabled": s.get("RotationEnabled", False),
                    "rotation_lambda": s.get("RotationLambdaARN"),
                    "rotation_rules": s.get("RotationRules"),
                    "last_rotated": s.get("LastRotatedDate"),
                    "last_changed": s.get("LastChangedDate"),
                    "last_accessed": s.get("LastAccessedDate"),
                    "owning_service": s.get("OwningService"),
                    "tags": {t.get("Key"): t.get("Value") for t in s.get("Tags") or []},
                }
                if focused:
                    pol = await safe(sm.get_resource_policy(SecretId=arn))
                    body = (pol or {}).get("ResourcePolicy")
                    if isinstance(body, str) and body:
                        try:
                            row["policy_document"] = json.loads(body)
                        except ValueError:
                            row["policy_document"] = {"_raw": body}
                    versions = await safe(
                        sm.list_secret_version_ids(SecretId=arn, IncludeDeprecated=False)
                    )
                    row["version_count"] = len((versions or {}).get("Versions") or [])
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "secret_count": len(secrets),
            "secrets_without_rotation": sum(
                1 for s in secrets if not s.get("RotationEnabled")
            ),
        }
