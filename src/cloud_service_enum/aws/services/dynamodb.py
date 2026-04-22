"""DynamoDB tables."""

from __future__ import annotations

import json
from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class DynamoDbService(AwsService):
    service_name = "dynamodb"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        names: list[str] = []
        async with ctx.client("dynamodb") as ddb:
            for page in await paginate(ddb, "list_tables"):
                names.extend(page.get("TableNames", []))
            for n in names:
                desc = (await safe(ddb.describe_table(TableName=n))) or {}
                ct = (await safe(ddb.describe_continuous_backups(TableName=n))) or {}
                t = desc.get("Table") or {}
                pitr = (ct.get("ContinuousBackupsDescription") or {}).get(
                    "PointInTimeRecoveryDescription", {}
                )
                row: dict[str, Any] = {
                    "kind": "table",
                    "id": t.get("TableArn") or n,
                    "arn": t.get("TableArn"),
                    "name": n,
                    "region": ctx.region,
                    "status": t.get("TableStatus"),
                    "item_count": t.get("ItemCount"),
                    "size_bytes": t.get("TableSizeBytes"),
                    "billing_mode": (t.get("BillingModeSummary") or {}).get("BillingMode"),
                    "encryption": (t.get("SSEDescription") or {}).get("Status"),
                    "kms_key": (t.get("SSEDescription") or {}).get("KMSMasterKeyArn"),
                    "pitr_enabled": pitr.get("PointInTimeRecoveryStatus") == "ENABLED",
                    "deletion_protection": t.get("DeletionProtectionEnabled", False),
                    "stream_enabled": (t.get("StreamSpecification") or {}).get(
                        "StreamEnabled", False
                    ),
                    "stream_arn": t.get("LatestStreamArn"),
                }
                if focused and t.get("TableArn"):
                    pol = await safe(ddb.get_resource_policy(ResourceArn=t["TableArn"]))
                    body = (pol or {}).get("Policy")
                    if isinstance(body, str) and body:
                        try:
                            row["policy_document"] = json.loads(body)
                        except ValueError:
                            row["policy_document"] = {"_raw": body}
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "table_count": len(names),
            "tables_without_pitr": sum(
                1 for r in result.resources if r.get("kind") == "table" and not r.get("pitr_enabled")
            ),
        }
