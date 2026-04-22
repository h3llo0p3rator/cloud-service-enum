"""AWS Glue databases, crawlers and security configurations."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class GlueService(AwsService):
    service_name = "glue"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("glue") as glue:
            databases = collect_items(await paginate(glue, "get_databases"), "DatabaseList")
            crawlers = collect_items(await paginate(glue, "get_crawlers"), "Crawlers")
            jobs = collect_items(await paginate(glue, "get_jobs"), "Jobs")
            sec_resp = await safe(glue.get_security_configurations())
            data_catalog = await safe(glue.get_data_catalog_encryption_settings())
            connections = []
            if focused:
                conn_resp = await safe(glue.get_connections())
                connections = (conn_resp or {}).get("ConnectionList", []) or []
        for d in databases:
            result.resources.append(
                {
                    "kind": "database",
                    "id": d["Name"],
                    "name": d["Name"],
                    "region": ctx.region,
                    "description": d.get("Description"),
                }
            )
        for c in crawlers:
            result.resources.append(
                {
                    "kind": "crawler",
                    "id": c["Name"],
                    "region": ctx.region,
                    "role": c.get("Role"),
                    "state": c.get("State"),
                }
            )
        for j in jobs:
            row = {
                "kind": "job",
                "id": j["Name"],
                "region": ctx.region,
                "role": j.get("Role"),
                "security_config": j.get("SecurityConfiguration"),
                "max_retries": j.get("MaxRetries"),
            }
            if focused:
                cmd = j.get("Command") or {}
                row["script_location"] = cmd.get("ScriptLocation")
                row["language"] = cmd.get("Name")
                if j.get("DefaultArguments"):
                    row["env_vars"] = dict(j["DefaultArguments"])
            result.resources.append(row)
        for c in connections:
            props = (c.get("ConnectionProperties") or {}).copy()
            result.resources.append(
                {
                    "kind": "connection",
                    "id": c.get("Name"),
                    "name": c.get("Name"),
                    "region": ctx.region,
                    "type": c.get("ConnectionType"),
                    "match_criteria": c.get("MatchCriteria"),
                    "physical_requirements": c.get("PhysicalConnectionRequirements"),
                    "env_vars": props,
                }
            )
        catalog = (data_catalog or {}).get("DataCatalogEncryptionSettings") or {}
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "database_count": len(databases),
            "crawler_count": len(crawlers),
            "job_count": len(jobs),
            "security_config_count": len((sec_resp or {}).get("SecurityConfigurations", [])),
            "catalog_at_rest_encryption": (
                (catalog.get("EncryptionAtRest") or {}).get("CatalogEncryptionMode")
            ),
            "catalog_connection_password_encryption": (
                (catalog.get("ConnectionPasswordEncryption") or {}).get(
                    "ReturnConnectionPasswordEncrypted", False
                )
            ),
        }
