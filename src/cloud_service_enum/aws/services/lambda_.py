"""Lambda functions."""

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
from cloud_service_enum.core.secrets import scan_mapping

_DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
    "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0",
    "ruby2.5", "ruby2.7",
    "go1.x",
}


class LambdaService(AwsService):
    service_name = "lambda"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("lambda") as client:
            pages = await paginate(client, "list_functions")
            funcs = collect_items(pages, "Functions")
            for fn in funcs:
                row = self._row(fn, ctx.region)
                if focused:
                    await self._enrich(client, fn, row, ctx.scope.secret_scan)
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "function_count": len(funcs),
            "deprecated_runtimes": sum(
                1 for fn in funcs if fn.get("Runtime") in _DEPRECATED_RUNTIMES
            ),
        }

    @staticmethod
    def _row(fn: dict[str, Any], region: str) -> dict[str, Any]:
        env_keys = list((fn.get("Environment") or {}).get("Variables") or {})
        return {
            "kind": "function",
            "id": fn["FunctionArn"],
            "arn": fn["FunctionArn"],
            "name": fn["FunctionName"],
            "region": region,
            "runtime": fn.get("Runtime"),
            "handler": fn.get("Handler"),
            "timeout": fn.get("Timeout"),
            "memory": fn.get("MemorySize"),
            "role": fn.get("Role"),
            "kms_key": fn.get("KMSKeyArn"),
            "vpc": fn.get("VpcConfig", {}).get("VpcId"),
            "tracing": fn.get("TracingConfig", {}).get("Mode"),
            "env_var_keys": env_keys,
            "last_modified": fn.get("LastModified"),
            "package_type": fn.get("PackageType"),
            "architectures": fn.get("Architectures"),
        }

    async def _enrich(
        self, client: Any, fn: dict[str, Any], row: dict[str, Any], secret_scan: bool
    ) -> None:
        name = fn["FunctionName"]
        env_vars = (fn.get("Environment") or {}).get("Variables") or {}
        if env_vars:
            row["env_vars"] = dict(env_vars)
            if secret_scan:
                hits = scan_mapping(name, env_vars)
                if hits:
                    row["secrets_found"] = [h.as_dict() for h in hits]
        policy_resp = await safe(client.get_policy(FunctionName=name))
        body = (policy_resp or {}).get("Policy")
        if isinstance(body, str) and body:
            try:
                row["policy_document"] = json.loads(body)
            except ValueError:
                row["policy_document"] = {"_raw": body}
        url = await safe(client.get_function_url_config(FunctionName=name))
        if url:
            row["function_url"] = url.get("FunctionUrl")
            row["function_url_auth"] = url.get("AuthType")
            row["function_url_cors"] = url.get("Cors")
        sources = await safe(client.list_event_source_mappings(FunctionName=name))
        if sources:
            row["event_sources"] = [
                {
                    "uuid": esm.get("UUID"),
                    "source": esm.get("EventSourceArn"),
                    "state": esm.get("State"),
                    "batch_size": esm.get("BatchSize"),
                }
                for esm in sources.get("EventSourceMappings") or []
            ]
