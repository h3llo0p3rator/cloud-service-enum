"""Lambda functions."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

from cloud_service_enum.aws.base import (
    AwsService,
    ServiceContext,
    collect_items,
    paginate,
    safe,
)
from cloud_service_enum.core.models import Scope, ServiceResult
from cloud_service_enum.core.secrets import TEXT_EXTENSIONS, scan_mapping, scan_text

_DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
    "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0",
    "ruby2.5", "ruby2.7",
    "go1.x",
}

# Additional extensions we always try to decode for Lambda code review even
# if they're not in the shared ``TEXT_EXTENSIONS`` set.
_CODE_TEXT_EXTENSIONS: frozenset[str] = TEXT_EXTENSIONS | frozenset(
    {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".kt"}
)
_EXCERPT_LINES = 80


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
                    await self._enrich(client, fn, row, ctx.scope)
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
        self, client: Any, fn: dict[str, Any], row: dict[str, Any], scope: Scope
    ) -> None:
        name = fn["FunctionName"]
        secret_scan = scope.secret_scan
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
        if scope.lambda_code:
            await _fetch_code(client, fn, row, scope)


async def _fetch_code(
    client: Any, fn: dict[str, Any], row: dict[str, Any], scope: Scope
) -> None:
    """Follow ``Code.Location`` and surface text-file excerpts + secrets.

    Silently skips non-zip packages (container images) and downloads that
    exceed the configured byte budget; annotates the row with a short note
    so the operator can see why nothing was extracted.
    """
    name = fn["FunctionName"]
    details = await safe(client.get_function(FunctionName=name))
    if not details:
        return
    code_info = details.get("Code") or {}
    location = code_info.get("Location")
    repository_type = code_info.get("RepositoryType")
    if not location or repository_type not in {"S3", None}:
        row["code_status"] = f"skipped: RepositoryType={repository_type or 'unknown'}"
        return

    import httpx  # local import keeps module load cheap

    size_limit_bytes = scope.lambda_code_size_limit_mb * 1024 * 1024
    try:
        async with httpx.AsyncClient(timeout=scope.timeout_s, follow_redirects=True) as http:
            resp = await http.get(location)
            resp.raise_for_status()
            payload = resp.content
    except Exception as exc:  # noqa: BLE001
        row["code_status"] = f"fetch failed: {type(exc).__name__}: {exc}"
        return

    row["code_size"] = len(payload)
    if len(payload) > size_limit_bytes:
        row["code_status"] = (
            f"skipped: size {len(payload) // (1024 * 1024)} MB exceeds "
            f"{scope.lambda_code_size_limit_mb} MB limit"
        )
        return

    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile:
        row["code_status"] = "skipped: not a valid zip (container image?)"
        return

    handler_module = (fn.get("Handler") or "").rsplit(".", 1)[0]
    file_size_limit = scope.lambda_code_file_size_limit_kb * 1024
    code_files: list[dict[str, Any]] = []
    file_findings: list[dict[str, Any]] = []
    handler_excerpt: str | None = None

    for info in archive.infolist():
        if info.is_dir():
            continue
        entry: dict[str, Any] = {"path": info.filename, "size": info.file_size}
        ext = _ext(info.filename)
        if ext not in _CODE_TEXT_EXTENSIONS:
            code_files.append(entry)
            continue
        if info.file_size > file_size_limit:
            entry["note"] = f"size {info.file_size} bytes exceeds file limit"
            code_files.append(entry)
            continue
        try:
            raw = archive.read(info.filename)
        except Exception as exc:  # noqa: BLE001
            entry["note"] = f"read failed: {type(exc).__name__}"
            code_files.append(entry)
            continue
        text = raw.decode("utf-8", errors="replace")
        entry["excerpt"] = _head(text, _EXCERPT_LINES)
        hits = scan_text(f"{name}!{info.filename}", text)
        if hits:
            finding_dicts = [h.as_dict() for h in hits]
            entry["secrets_found"] = finding_dicts
            file_findings.extend(finding_dicts)
        if handler_module and (
            info.filename == f"{handler_module}.py"
            or info.filename == f"{handler_module}.js"
            or info.filename == f"{handler_module}.mjs"
            or info.filename == f"{handler_module}.ts"
        ):
            handler_excerpt = entry["excerpt"]
            entry["is_handler"] = True
        code_files.append(entry)

    archive.close()
    row["code_files"] = code_files
    row["code_file_count"] = len(code_files)
    if handler_excerpt:
        row["handler_excerpt"] = handler_excerpt
    if file_findings:
        existing = row.setdefault("secrets_found", [])
        existing.extend(file_findings)


def _ext(path: str) -> str:
    dot = path.rfind(".")
    return path[dot:].lower() if dot >= 0 else ""


def _head(text: str, max_lines: int) -> str:
    """Return the first ``max_lines`` lines of ``text`` joined back together."""
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[:max_lines]) + f"\n… ({len(lines) - max_lines} more lines)"
