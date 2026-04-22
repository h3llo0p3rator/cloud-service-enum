"""Amazon Inspector v2 status and coverage."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class InspectorService(AwsService):
    service_name = "inspector"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("inspector2") as insp:
            status = (await safe(insp.batch_get_account_status())) or {}
            findings = await safe(insp.list_finding_aggregations(aggregationType="TITLE", maxResults=50))
        accounts = status.get("accounts", []) or []
        for acct in accounts:
            state = (acct.get("state") or {}).get("status")
            result.resources.append(
                {
                    "kind": "account-status",
                    "id": acct.get("accountId"),
                    "region": ctx.region,
                    "state": state,
                    "resource_status": acct.get("resourceState"),
                }
            )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "account_count": len(accounts),
            "enabled": any(
                (a.get("state") or {}).get("status") == "ENABLED" for a in accounts
            ),
            "top_finding_titles": [
                f.get("titleAggregation", {}).get("title")
                for f in ((findings or {}).get("responses") or [])[:10]
            ],
        }
