"""KMS customer managed keys."""

from __future__ import annotations

import json
from typing import Any

from cloud_service_enum.aws.base import (
    AwsService,
    ServiceContext,
    collect_items,
    paginate,
    safe,
)
from cloud_service_enum.core.models import ServiceResult


class KmsService(AwsService):
    service_name = "kms"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("kms") as kms:
            keys = collect_items(await paginate(kms, "list_keys"), "Keys")
            aliases = collect_items(await paginate(kms, "list_aliases"), "Aliases")
            aliases_by_key: dict[str, list[str]] = {}
            for a in aliases:
                target = a.get("TargetKeyId")
                if target:
                    aliases_by_key.setdefault(target, []).append(a.get("AliasName"))
            for k in keys:
                key_id = k["KeyId"]
                desc = (await safe(kms.describe_key(KeyId=key_id))) or {}
                meta = desc.get("KeyMetadata") or {}
                rotation = await safe(kms.get_key_rotation_status(KeyId=key_id))
                if meta.get("KeyManager") != "CUSTOMER":
                    continue
                row: dict[str, Any] = {
                    "kind": "key",
                    "id": meta["KeyId"],
                    "arn": meta["Arn"],
                    "region": ctx.region,
                    "state": meta.get("KeyState"),
                    "enabled": meta.get("Enabled"),
                    "rotation_enabled": (rotation or {}).get("KeyRotationEnabled", False),
                    "spec": meta.get("KeySpec"),
                    "usage": meta.get("KeyUsage"),
                    "multi_region": meta.get("MultiRegion", False),
                    "origin": meta.get("Origin"),
                    "aliases": aliases_by_key.get(meta["KeyId"], []),
                }
                if focused:
                    await self._enrich(kms, key_id, row)
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "customer_key_count": sum(1 for r in result.resources if r.get("kind") == "key"),
            "keys_without_rotation": sum(
                1 for r in result.resources if r.get("kind") == "key" and not r.get("rotation_enabled")
            ),
        }

    @staticmethod
    async def _enrich(kms: Any, key_id: str, row: dict[str, Any]) -> None:
        pol = await safe(kms.get_key_policy(KeyId=key_id, PolicyName="default"))
        body = (pol or {}).get("Policy")
        if isinstance(body, str) and body:
            try:
                row["policy_document"] = json.loads(body)
            except ValueError:
                row["policy_document"] = {"_raw": body}
        grants = await safe(kms.list_grants(KeyId=key_id))
        if grants:
            row["grants"] = [
                {
                    "grant_id": g.get("GrantId"),
                    "grantee": g.get("GranteePrincipal"),
                    "operations": g.get("Operations"),
                }
                for g in grants.get("Grants") or []
            ]
