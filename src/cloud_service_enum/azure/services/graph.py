"""Microsoft Graph users and groups (directory enumeration).

Also exposes MFA posture via authentication method registrations; the
``fix cse azure users`` bug from v1 is addressed by this module being a
first-class registered service (``cse azure enumerate -s graph``).
"""

from __future__ import annotations

from typing import Any

try:
    from msgraph import GraphServiceClient
except ImportError:  # pragma: no cover - optional
    GraphServiceClient = None  # type: ignore[assignment,misc]

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService
from cloud_service_enum.core.models import ServiceResult


class GraphService(AzureService):
    service_name = "graph"
    tenant_scoped = True

    async def collect_tenant(
        self, auth: AzureAuthenticator, result: ServiceResult
    ) -> None:
        if GraphServiceClient is None:
            result.errors.append("msgraph-sdk not installed")
            return
        client = GraphServiceClient(credentials=auth.credential(), scopes=["https://graph.microsoft.com/.default"])

        users = await _drain_users(client)
        groups = await _drain_groups(client)
        focused = self.is_focused_on()

        for u in users:
            row = {
                "kind": "user",
                "id": u.id,
                "name": u.display_name,
                "user_principal_name": u.user_principal_name,
                "account_enabled": u.account_enabled,
                "mail": u.mail,
                "user_type": u.user_type,
                "created": u.created_date_time.isoformat() if u.created_date_time else None,
            }
            if focused and u.id:
                try:
                    methods = await client.users.by_user_id(u.id).authentication.methods.get()
                    method_types = []
                    for m in (methods.value or []) if methods else []:
                        odata = getattr(m, "odata_type", "")
                        method_types.append(odata.replace("#microsoft.graph.", ""))
                    row["env_vars"] = {
                        "auth_methods": ", ".join(method_types) or "password (default)",
                    }
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(row)
        for g in groups:
            grow = {
                "kind": "group",
                "id": g.id,
                "name": g.display_name,
                "security_enabled": g.security_enabled,
                "mail_enabled": g.mail_enabled,
                "group_types": g.group_types,
            }
            if focused and g.id:
                try:
                    members = await client.groups.by_group_id(g.id).members.get()
                    grow["members"] = [
                        getattr(m, "user_principal_name", None) or getattr(m, "display_name", None)
                        for m in (members.value or [])
                        if members
                    ]
                    owners = await client.groups.by_group_id(g.id).owners.get()
                    grow["owners"] = [
                        getattr(m, "user_principal_name", None) or getattr(m, "display_name", None)
                        for m in (owners.value or [])
                        if owners
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(grow)

        result.cis_fields = {
            "user_count": len(users),
            "group_count": len(groups),
            "disabled_users": sum(1 for u in users if u.account_enabled is False),
            "guest_users": sum(1 for u in users if (u.user_type or "").lower() == "guest"),
        }


async def _drain_users(client: Any) -> list[Any]:
    resp = await client.users.get()
    out: list[Any] = []
    while resp is not None:
        out.extend(resp.value or [])
        if not getattr(resp, "odata_next_link", None):
            break
        resp = await client.users.with_url(resp.odata_next_link).get()
    return out


async def _drain_groups(client: Any) -> list[Any]:
    resp = await client.groups.get()
    out: list[Any] = []
    while resp is not None:
        out.extend(resp.value or [])
        if not getattr(resp, "odata_next_link", None):
            break
        resp = await client.groups.with_url(resp.odata_next_link).get()
    return out
