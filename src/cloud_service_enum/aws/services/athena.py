"""Athena — workgroups, named queries, data catalogs.

Saved queries often contain literal table names + predicate filters that
hint at where sensitive data lives. Workgroup result-location buckets
are frequently under-protected and worth cross-referencing with the S3
scanner.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult

_BATCH = 50


class AthenaService(AwsService):
    service_name = "athena"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("athena") as athena:
            workgroups = await _page(athena, "list_work_groups", "WorkGroups")
            for wg in workgroups:
                row = await _workgroup_row(athena, wg, ctx.region, focused)
                result.resources.append(row)

            catalogs = await _page(athena, "list_data_catalogs", "DataCatalogsSummary")
            for cat in catalogs:
                row = await _catalog_row(athena, cat, ctx.region, focused)
                result.resources.append(row)

            if focused:
                for wg in workgroups:
                    wg_name = wg.get("Name")
                    if not wg_name:
                        continue
                    queries = await _named_queries(athena, wg_name)
                    for q in queries:
                        result.resources.append(_query_row(q, ctx.region))

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "workgroup_count": len(workgroups),
            "data_catalog_count": len(catalogs),
        }


async def _page(
    client: Any, op: str, key: str, **kwargs: Any
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["NextToken"] = next_token
        resp = await safe(getattr(client, op)(**call_kwargs))
        if not resp:
            break
        items.extend(resp.get(key, []) or [])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


async def _workgroup_row(
    athena: Any, wg: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    name = wg.get("Name")
    row: dict[str, Any] = {
        "kind": "athena-workgroup",
        "id": name,
        "name": name,
        "region": region,
        "state": wg.get("State"),
        "description": wg.get("Description"),
    }
    if not focused or not name:
        return row
    detail = await safe(athena.get_work_group(WorkGroup=name))
    if not detail:
        return row
    body = detail.get("WorkGroup") or {}
    config = body.get("Configuration") or {}
    result_cfg = config.get("ResultConfiguration") or {}
    row["result_location"] = result_cfg.get("OutputLocation")
    row["result_encryption"] = (
        result_cfg.get("EncryptionConfiguration") or {}
    ).get("EncryptionOption")
    row["result_kms_key"] = (
        result_cfg.get("EncryptionConfiguration") or {}
    ).get("KmsKey")
    row["enforce_workgroup_config"] = config.get(
        "EnforceWorkGroupConfiguration", False
    )
    row["publish_cloudwatch_metrics"] = config.get(
        "PublishCloudWatchMetricsEnabled", False
    )
    row["bytes_scanned_cutoff_per_query"] = config.get(
        "BytesScannedCutoffPerQuery"
    )
    row["engine_version"] = (
        config.get("EngineVersion") or {}
    ).get("EffectiveEngineVersion")
    return row


async def _catalog_row(
    athena: Any, cat: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    name = cat.get("CatalogName")
    row: dict[str, Any] = {
        "kind": "athena-data-catalog",
        "id": name,
        "name": name,
        "region": region,
        "type": cat.get("Type"),
    }
    if not focused or not name:
        return row
    detail = await safe(athena.get_data_catalog(Name=name))
    body = (detail or {}).get("DataCatalog") or {}
    row["description"] = body.get("Description")
    row["parameters"] = body.get("Parameters") or {}
    return row


async def _named_queries(athena: Any, workgroup: str) -> list[dict[str, Any]]:
    query_ids: list[str] = []
    next_token: str | None = None
    while True:
        call_kwargs: dict[str, Any] = {"WorkGroup": workgroup, "MaxResults": _BATCH}
        if next_token:
            call_kwargs["NextToken"] = next_token
        resp = await safe(athena.list_named_queries(**call_kwargs))
        if not resp:
            break
        query_ids.extend(resp.get("NamedQueryIds", []) or [])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    out: list[dict[str, Any]] = []
    for chunk_start in range(0, len(query_ids), _BATCH):
        chunk = query_ids[chunk_start : chunk_start + _BATCH]
        resp = await safe(athena.batch_get_named_query(NamedQueryIds=chunk))
        out.extend((resp or {}).get("NamedQueries", []) or [])
    return out


def _query_row(query: dict[str, Any], region: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "kind": "athena-named-query",
        "id": query.get("NamedQueryId"),
        "name": query.get("Name"),
        "region": region,
        "description": query.get("Description"),
        "workgroup": query.get("WorkGroup"),
        "database": query.get("Database"),
    }
    body = query.get("QueryString")
    if isinstance(body, str) and body:
        row["definition"] = body
        row["definition_language"] = "sql"
    return row
