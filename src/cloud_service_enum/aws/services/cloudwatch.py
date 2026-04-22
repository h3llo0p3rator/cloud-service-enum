"""CloudWatch alarms and log groups."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class CloudWatchService(AwsService):
    service_name = "cloudwatch"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("cloudwatch") as cw:
            alarm_pages = await paginate(cw, "describe_alarms")
            dashboards = []
            if focused:
                resp = await safe(cw.list_dashboards())
                dashboards = (resp or {}).get("DashboardEntries", []) or []
        alarms = collect_items(alarm_pages, "MetricAlarms") + collect_items(
            alarm_pages, "CompositeAlarms"
        )
        for a in alarms:
            result.resources.append(
                {
                    "kind": "alarm",
                    "id": a.get("AlarmArn") or a["AlarmName"],
                    "name": a["AlarmName"],
                    "region": ctx.region,
                    "state": a.get("StateValue"),
                    "metric": a.get("MetricName"),
                    "namespace": a.get("Namespace"),
                    "actions": a.get("AlarmActions", []),
                }
            )

        async with ctx.client("logs") as logs:
            log_groups = collect_items(await paginate(logs, "describe_log_groups"), "logGroups")
        for g in log_groups:
            result.resources.append(
                {
                    "kind": "log-group",
                    "id": g["arn"],
                    "name": g["logGroupName"],
                    "region": ctx.region,
                    "retention_days": g.get("retentionInDays"),
                    "kms_key_id": g.get("kmsKeyId"),
                    "stored_bytes": g.get("storedBytes"),
                }
            )

        for d in dashboards:
            result.resources.append(
                {
                    "kind": "dashboard",
                    "id": d.get("DashboardArn") or d.get("DashboardName"),
                    "name": d.get("DashboardName"),
                    "region": ctx.region,
                    "size_bytes": d.get("Size"),
                    "last_modified": d.get("LastModified"),
                }
            )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "alarm_count": len(alarms),
            "log_group_count": len(log_groups),
            "unencrypted_log_groups": sum(1 for g in log_groups if not g.get("kmsKeyId")),
            "log_groups_without_retention": sum(1 for g in log_groups if not g.get("retentionInDays")),
        }
