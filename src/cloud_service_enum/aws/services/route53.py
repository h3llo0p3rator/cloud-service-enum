"""Route 53 hosted zones and health checks (global)."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class Route53Service(AwsService):
    service_name = "route53"
    is_regional = False

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("route53") as r53:
            zones = collect_items(await paginate(r53, "list_hosted_zones"), "HostedZones")
            hc_pages = await paginate(r53, "list_health_checks")
            hcs = collect_items(hc_pages, "HealthChecks")
            query_log_pages = await safe(paginate(r53, "list_query_logging_configs"))
            query_logs = collect_items(query_log_pages or [], "QueryLoggingConfigs")
            zone_records: dict[str, list[dict]] = {}
            if focused:
                for z in zones:
                    pages = await safe(
                        paginate(r53, "list_resource_record_sets", HostedZoneId=z["Id"])
                    )
                    if pages:
                        zone_records[z["Id"]] = collect_items(
                            pages, "ResourceRecordSets"
                        )

        for z in zones:
            row: dict = {
                "kind": "hosted-zone",
                "id": z["Id"],
                "name": z["Name"],
                "private": (z.get("Config") or {}).get("PrivateZone", False),
                "record_count": z.get("ResourceRecordSetCount"),
            }
            if focused and z["Id"] in zone_records:
                row["records"] = [
                    {
                        "name": r.get("Name"),
                        "type": r.get("Type"),
                        "ttl": r.get("TTL"),
                        "values": [
                            v.get("Value") for v in (r.get("ResourceRecords") or [])
                        ]
                        or (
                            [r["AliasTarget"].get("DNSName")]
                            if r.get("AliasTarget")
                            else []
                        ),
                    }
                    for r in zone_records[z["Id"]]
                ]
            result.resources.append(row)
        for h in hcs:
            cfg = h.get("HealthCheckConfig") or {}
            result.resources.append(
                {
                    "kind": "health-check",
                    "id": h["Id"],
                    "type": cfg.get("Type"),
                    "target": cfg.get("FullyQualifiedDomainName") or cfg.get("IPAddress"),
                }
            )
        zones_with_logging = {q["HostedZoneId"] for q in query_logs}
        result.cis_fields = {
            "zone_count": len(zones),
            "zones_with_query_logging": len(zones_with_logging),
            "zones_missing_query_logging": [
                z["Id"].split("/")[-1] for z in zones if z["Id"].split("/")[-1] not in zones_with_logging
            ],
        }
