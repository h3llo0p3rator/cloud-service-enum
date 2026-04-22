"""CloudFormation stacks and stack sets."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class CloudFormationService(AwsService):
    service_name = "cloudformation"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("cloudformation") as cfn:
            stacks = collect_items(await paginate(cfn, "describe_stacks"), "Stacks")
            for s in stacks:
                row = {
                    "kind": "stack",
                    "id": s["StackId"],
                    "name": s["StackName"],
                    "region": ctx.region,
                    "status": s.get("StackStatus"),
                    "role_arn": s.get("RoleARN"),
                    "drift_status": (s.get("DriftInformation") or {}).get("StackDriftStatus"),
                    "termination_protection": s.get("EnableTerminationProtection", False),
                    "capabilities": s.get("Capabilities", []),
                    "created": s.get("CreationTime"),
                    "last_updated": s.get("LastUpdatedTime"),
                }
                if focused:
                    template = await safe(cfn.get_template(StackName=s["StackName"]))
                    body = (template or {}).get("TemplateBody")
                    if body is not None:
                        row["definition"] = body
                        row["definition_language"] = (
                            "json" if isinstance(body, (dict, list)) else "yaml"
                        )
                    res_list = await safe(
                        cfn.list_stack_resources(StackName=s["StackName"])
                    )
                    if res_list:
                        row["stack_resources"] = [
                            {
                                "logical_id": r.get("LogicalResourceId"),
                                "physical_id": r.get("PhysicalResourceId"),
                                "type": r.get("ResourceType"),
                                "status": r.get("ResourceStatus"),
                            }
                            for r in res_list.get("StackResourceSummaries") or []
                        ]
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "stack_count": len(stacks),
            "unprotected_stacks": sum(
                1 for s in stacks if not s.get("EnableTerminationProtection")
            ),
        }
