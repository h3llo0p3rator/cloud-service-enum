"""AWS Organizations: describe org, accounts, policies, delegated administrators."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class OrganizationsService(AwsService):
    service_name = "organizations"
    is_regional = False

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("organizations") as org:
            desc = await safe(org.describe_organization())
            org_info = (desc or {}).get("Organization") or {}
            if org_info:
                result.resources.append(
                    {
                        "kind": "organization",
                        "id": org_info.get("Id"),
                        "arn": org_info.get("Arn"),
                        "master_account_id": org_info.get("MasterAccountId"),
                        "feature_set": org_info.get("FeatureSet"),
                        "available_policy_types": org_info.get("AvailablePolicyTypes"),
                    }
                )
                accounts = collect_items(await paginate(org, "list_accounts"), "Accounts")
                for a in accounts:
                    result.resources.append(
                        {
                            "kind": "account",
                            "id": a["Id"],
                            "arn": a.get("Arn"),
                            "name": a.get("Name"),
                            "email": a.get("Email"),
                            "status": a.get("Status"),
                            "joined": a.get("JoinedTimestamp"),
                        }
                    )
                for policy_type in (
                    "SERVICE_CONTROL_POLICY",
                    "TAG_POLICY",
                    "BACKUP_POLICY",
                    "AISERVICES_OPT_OUT_POLICY",
                ):
                    resp = await safe(org.list_policies(Filter=policy_type))
                    for p in (resp or {}).get("Policies", []):
                        row = {
                            "kind": "policy",
                            "id": p["Id"],
                            "name": p.get("Name"),
                            "type": policy_type,
                            "aws_managed": p.get("AwsManaged", False),
                        }
                        detail = await safe(org.describe_policy(PolicyId=p["Id"]))
                        body = ((detail or {}).get("Policy") or {}).get("Content")
                        if isinstance(body, str) and body:
                            try:
                                row["policy_document"] = __import__("json").loads(body)
                            except ValueError:
                                row["policy_document"] = {"_raw": body}
                        targets = await safe(org.list_targets_for_policy(PolicyId=p["Id"]))
                        if targets:
                            row["targets"] = [
                                {
                                    "id": t.get("TargetId"),
                                    "type": t.get("Type"),
                                    "name": t.get("Name"),
                                }
                                for t in targets.get("Targets") or []
                            ]
                        result.resources.append(row)
                delegated = await safe(org.list_delegated_administrators())
                for d in (delegated or {}).get("DelegatedAdministrators", []) or []:
                    result.resources.append(
                        {
                            "kind": "delegated-admin",
                            "id": d.get("Id"),
                            "name": d.get("Name"),
                            "email": d.get("Email"),
                            "joined": d.get("JoinedTimestamp"),
                        }
                    )

                result.cis_fields = {
                    "is_organization_master": org_info.get("MasterAccountId") is not None,
                    "account_count": len([r for r in result.resources if r.get("kind") == "account"]),
                    "scp_count": len(
                        [r for r in result.resources if r.get("kind") == "policy" and r.get("type") == "SERVICE_CONTROL_POLICY"]
                    ),
                }
            else:
                result.cis_fields = {"is_organization_master": False}
