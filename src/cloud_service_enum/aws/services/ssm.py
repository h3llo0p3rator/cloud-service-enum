"""SSM — parameter store, session-manager targets, command history, documents.

Parameter Store is where teams tend to dump long-lived credentials that
they would never think to put in Secrets Manager. Focused + secret-scan
mode decrypts SecureString parameters, regex-scans the plaintext and
surfaces only the findings — the raw plaintext never hits the row,
terminal or JSON report.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import (
    AwsService,
    ServiceContext,
    collect_items,
    paginate,
    safe,
)
from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.core.secrets import mask, scan_text

_GET_PARAMETERS_BATCH = 10
_COMMAND_HISTORY_CAP = 25


class SsmService(AwsService):
    service_name = "ssm"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        secret_scan = ctx.scope.secret_scan
        async with ctx.client("ssm") as ssm:
            parameters = collect_items(
                await paginate(ssm, "describe_parameters"), "Parameters"
            )
            param_rows = [_parameter_row(p, ctx.region) for p in parameters]
            if focused and secret_scan:
                await _decrypt_and_scan(ssm, param_rows)
            result.resources.extend(param_rows)

            instances = collect_items(
                await paginate(
                    ssm,
                    "describe_instance_information",
                    Filters=[{"Key": "PingStatus", "Values": ["Online"]}],
                ),
                "InstanceInformationList",
            )
            for inst in instances:
                result.resources.append(_instance_row(inst, ctx.region))

            if focused:
                commands = await _recent_commands(ssm)
                for cmd in commands:
                    result.resources.append(_command_row(cmd, ctx.region))

                docs = collect_items(
                    await paginate(
                        ssm,
                        "list_documents",
                        Filters=[{"Key": "Owner", "Values": ["Self"]}],
                    ),
                    "DocumentIdentifiers",
                )
                for doc in docs:
                    row = await _document_row(ssm, doc, ctx.region)
                    result.resources.append(row)

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "parameter_count": len(parameters),
            "secure_string_count": sum(
                1 for p in parameters if p.get("Type") == "SecureString"
            ),
            "online_instance_count": len(instances),
        }


def _parameter_row(param: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "kind": "ssm-parameter",
        "id": param.get("Name"),
        "arn": param.get("ARN"),
        "name": param.get("Name"),
        "region": region,
        "type": param.get("Type"),
        "tier": param.get("Tier"),
        "key_id": param.get("KeyId"),
        "last_modified_user": param.get("LastModifiedUser"),
        "last_modified": param.get("LastModifiedDate"),
        "version": param.get("Version"),
        "description": param.get("Description"),
    }


async def _decrypt_and_scan(ssm: Any, rows: list[dict[str, Any]]) -> None:
    """Decrypt parameter values, regex-scan them and attach findings only.

    The raw plaintext is deliberately dropped — only a masked preview and
    the structured findings stay on the row.
    """
    names_by_index: dict[str, int] = {}
    for idx, row in enumerate(rows):
        name = row.get("name")
        if isinstance(name, str):
            names_by_index[name] = idx
    names = list(names_by_index)
    for chunk_start in range(0, len(names), _GET_PARAMETERS_BATCH):
        chunk = names[chunk_start : chunk_start + _GET_PARAMETERS_BATCH]
        resp = await safe(ssm.get_parameters(Names=chunk, WithDecryption=True))
        for entry in (resp or {}).get("Parameters", []) or []:
            idx = names_by_index.get(entry.get("Name", ""))
            if idx is None:
                continue
            value = entry.get("Value")
            if not isinstance(value, str) or not value:
                continue
            row = rows[idx]
            row["value_preview"] = mask(value) if len(value) > 8 else "<redacted>"
            findings = scan_text(entry.get("Name") or "parameter", value)
            if findings:
                row["secrets_found"] = [f.as_dict() for f in findings]


def _instance_row(inst: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "kind": "ssm-instance",
        "id": inst.get("InstanceId"),
        "region": region,
        "platform": inst.get("PlatformType"),
        "platform_name": inst.get("PlatformName"),
        "platform_version": inst.get("PlatformVersion"),
        "agent_version": inst.get("AgentVersion"),
        "ping_status": inst.get("PingStatus"),
        "computer_name": inst.get("ComputerName"),
        "ip_address": inst.get("IPAddress"),
        "iam_role": inst.get("IamRole"),
        "last_ping": inst.get("LastPingDateTime"),
    }


async def _recent_commands(ssm: Any) -> list[dict[str, Any]]:
    resp = await safe(ssm.list_command_invocations(MaxResults=_COMMAND_HISTORY_CAP))
    return (resp or {}).get("CommandInvocations", []) or []


def _command_row(cmd: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "kind": "ssm-command",
        "id": cmd.get("CommandId"),
        "region": region,
        "document_name": cmd.get("DocumentName"),
        "document_version": cmd.get("DocumentVersion"),
        "instance_id": cmd.get("InstanceId"),
        "instance_name": cmd.get("InstanceName"),
        "status": cmd.get("Status"),
        "requested_at": cmd.get("RequestedDateTime"),
        "comment": cmd.get("Comment"),
    }


async def _document_row(
    ssm: Any, doc: dict[str, Any], region: str
) -> dict[str, Any]:
    name = doc.get("Name")
    row: dict[str, Any] = {
        "kind": "ssm-document",
        "id": name,
        "name": name,
        "region": region,
        "document_type": doc.get("DocumentType"),
        "document_format": doc.get("DocumentFormat"),
        "owner": doc.get("Owner"),
        "target_type": doc.get("TargetType"),
        "platform_types": doc.get("PlatformTypes") or [],
    }
    if not name:
        return row
    detail = await safe(ssm.get_document(Name=name))
    if not detail:
        return row
    content = detail.get("Content")
    if isinstance(content, str) and content:
        row["definition"] = content
        row["definition_language"] = (
            detail.get("DocumentFormat", "").lower() or "text"
        )
    return row
