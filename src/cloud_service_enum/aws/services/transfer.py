"""AWS Transfer Family — SFTP / FTPS / FTP servers, users, SSH keys.

Transfer Family users point at scoped-down S3 / EFS roles; an auditor
usually cares more about the ``role`` + ``policy`` attached to each
user than the user body itself. SSH public keys are captured in
focused mode so an auditor can correlate known attacker keys.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class TransferService(AwsService):
    service_name = "transfer"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("transfer") as tf:
            server_summaries = await _page(tf, "list_servers", "Servers")
            for summary in server_summaries:
                server_id = summary.get("ServerId")
                if not server_id:
                    continue
                row = await _server_row(tf, server_id, ctx.region)
                result.resources.append(row)
                users = await _page(
                    tf, "list_users", "Users", ServerId=server_id
                )
                for user in users:
                    result.resources.append(
                        await _user_row(tf, server_id, user, ctx.region, focused)
                    )

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "server_count": len(server_summaries),
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


async def _server_row(tf: Any, server_id: str, region: str) -> dict[str, Any]:
    detail = await safe(tf.describe_server(ServerId=server_id))
    body = (detail or {}).get("Server") or {}
    endpoint_details = body.get("EndpointDetails") or {}
    return {
        "kind": "transfer-server",
        "id": server_id,
        "arn": body.get("Arn"),
        "name": body.get("Tags", [{}])[0].get("Value") if body.get("Tags") else None,
        "region": region,
        "state": body.get("State"),
        "identity_provider_type": body.get("IdentityProviderType"),
        "endpoint_type": body.get("EndpointType"),
        "protocols": body.get("Protocols") or [],
        "domain": body.get("Domain"),
        "logging_role": body.get("LoggingRole"),
        "vpc_endpoint_id": endpoint_details.get("VpcEndpointId"),
        "vpc_id": endpoint_details.get("VpcId"),
        "subnet_ids": endpoint_details.get("SubnetIds") or [],
        "security_group_ids": endpoint_details.get("SecurityGroupIds") or [],
        "address_allocation_ids": endpoint_details.get("AddressAllocationIds") or [],
        "user_count": body.get("UserCount"),
        "host_key_fingerprint": body.get("HostKeyFingerprint"),
    }


async def _user_row(
    tf: Any,
    server_id: str,
    user: dict[str, Any],
    region: str,
    focused: bool,
) -> dict[str, Any]:
    username = user.get("UserName")
    row: dict[str, Any] = {
        "kind": "transfer-user",
        "id": user.get("Arn") or f"{server_id}/{username}",
        "arn": user.get("Arn"),
        "name": username,
        "region": region,
        "server_id": server_id,
        "role": user.get("Role"),
        "ssh_public_key_count": user.get("SshPublicKeyCount", 0),
        "home_directory": user.get("HomeDirectory"),
    }
    if focused and username:
        detail = await safe(tf.describe_user(ServerId=server_id, UserName=username))
        body = (detail or {}).get("User") or {}
        row["home_directory_type"] = body.get("HomeDirectoryType")
        row["home_directory_mappings"] = body.get("HomeDirectoryMappings") or []
        row["policy"] = body.get("Policy")
        row["posix_profile"] = body.get("PosixProfile") or {}
        ssh_keys = body.get("SshPublicKeys") or []
        if ssh_keys:
            row["ssh_public_keys"] = [
                {
                    "id": k.get("SshPublicKeyId"),
                    "body": k.get("SshPublicKeyBody"),
                    "date_imported": k.get("DateImported"),
                }
                for k in ssh_keys
            ]
    return row
