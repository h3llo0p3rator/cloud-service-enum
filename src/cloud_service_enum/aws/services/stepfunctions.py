"""Step Functions state machines."""

from __future__ import annotations

import json
from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class StepFunctionsService(AwsService):
    service_name = "stepfunctions"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("stepfunctions") as sfn:
            machines = collect_items(
                await paginate(sfn, "list_state_machines"), "stateMachines"
            )
            for m in machines:
                arn = m["stateMachineArn"]
                d = (await safe(sfn.describe_state_machine(stateMachineArn=arn))) or {}
                row: dict[str, Any] = {
                    "kind": "state-machine",
                    "id": arn,
                    "arn": arn,
                    "name": m["name"],
                    "region": ctx.region,
                    "type": m.get("type"),
                    "role_arn": d.get("roleArn"),
                    "logging_level": (d.get("loggingConfiguration") or {}).get("level"),
                    "tracing": (d.get("tracingConfiguration") or {}).get("enabled", False),
                }
                if focused:
                    body = d.get("definition")
                    if isinstance(body, str) and body:
                        try:
                            row["definition"] = json.loads(body)
                            row["definition_language"] = "json"
                        except ValueError:
                            row["definition"] = body
                            row["definition_language"] = "text"
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "state_machine_count": len(machines),
            "no_logging": sum(
                1
                for r in result.resources
                if r.get("kind") == "state-machine" and r.get("logging_level") in {None, "OFF"}
            ),
        }
