"""Administrative Units — AU metadata, members, scoped role assignments.

AUs let an org partition directory-role delegation; a scoped role
assignment on an AU effectively hands someone admin rights over *just*
the members of that AU. The scoped role members are the attacker-
relevant pivot so we resolve their role names via ``/directoryRoles``.
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

_MEMBER_CAP = 200


class AdministrativeUnitsService(AzureService):
    service_name = "administrative-unit"
    tenant_scoped = True

    async def collect_tenant(
        self, auth: AzureAuthenticator, result: ServiceResult
    ) -> None:
        if GraphServiceClient is None:
            result.errors.append("msgraph-sdk not installed")
            return
        client = GraphServiceClient(
            credentials=auth.credential(),
            scopes=["https://graph.microsoft.com/.default"],
        )
        units = await _drain_units(client)
        focused = self.is_focused_on()
        directory_roles = await _directory_role_lookup(client) if units else {}
        for unit in units:
            row = _unit_row(unit)
            if focused and unit.id:
                row["members"] = await _members(client, unit.id)
                row["role_bindings"] = await _scoped_role_members(
                    client, unit.id, directory_roles
                )
            result.resources.append(row)

        result.cis_fields = {
            "administrative_unit_count": len(units),
        }


async def _drain_units(client: Any) -> list[Any]:
    resp = await client.directory.administrative_units.get()
    out: list[Any] = []
    while resp is not None:
        out.extend(resp.value or [])
        next_link = getattr(resp, "odata_next_link", None)
        if not next_link:
            break
        resp = await client.directory.administrative_units.with_url(next_link).get()
    return out


def _unit_row(unit: Any) -> dict[str, Any]:
    return {
        "kind": "administrative-unit",
        "id": unit.id,
        "name": unit.display_name,
        "description": getattr(unit, "description", None),
        "visibility": getattr(unit, "visibility", None),
        "membership_type": getattr(unit, "membership_type", None),
        "membership_rule": getattr(unit, "membership_rule", None),
        "is_member_management_restricted": getattr(
            unit, "is_member_management_restricted", None
        ),
    }


async def _members(client: Any, unit_id: str) -> list[dict[str, Any]]:
    try:
        resp = await (
            client.directory.administrative_units.by_administrative_unit_id(unit_id)
            .members.get()
        )
    except Exception:  # noqa: BLE001
        return []
    members: list[dict[str, Any]] = []
    while resp is not None and len(members) < _MEMBER_CAP:
        for member in resp.value or []:
            members.append(
                {
                    "id": getattr(member, "id", None),
                    "display_name": getattr(member, "display_name", None),
                    "type": getattr(member, "odata_type", "").replace(
                        "#microsoft.graph.", ""
                    ),
                    "upn": getattr(member, "user_principal_name", None),
                }
            )
            if len(members) >= _MEMBER_CAP:
                break
        next_link = getattr(resp, "odata_next_link", None)
        if not next_link or len(members) >= _MEMBER_CAP:
            break
        try:
            resp = await (
                client.directory.administrative_units.by_administrative_unit_id(
                    unit_id
                ).members.with_url(next_link).get()
            )
        except Exception:  # noqa: BLE001
            break
    return members


async def _scoped_role_members(
    client: Any, unit_id: str, directory_roles: dict[str, str]
) -> list[dict[str, Any]]:
    try:
        resp = await (
            client.directory.administrative_units.by_administrative_unit_id(unit_id)
            .scoped_role_members.get()
        )
    except Exception:  # noqa: BLE001
        return []
    items = getattr(resp, "value", None) or []
    rows: list[dict[str, Any]] = []
    for item in items:
        role_id = getattr(item, "role_id", None)
        role_member = getattr(item, "role_member_info", None)
        rows.append(
            {
                "id": getattr(item, "id", None),
                "scope": unit_id,
                "role_id": role_id,
                "role_definition_id": role_id,
                "role_display_name": directory_roles.get(str(role_id) if role_id else "", None),
                "principal_id": getattr(role_member, "id", None) if role_member else None,
                "principal_display_name": (
                    getattr(role_member, "display_name", None) if role_member else None
                ),
            }
        )
    return rows


async def _directory_role_lookup(client: Any) -> dict[str, str]:
    """Build a ``role_template_id -> display_name`` cache for scoped members.

    ``scopedRoleMembers`` returns only the role template id; the
    auditor-facing label lives on ``/directoryRoles``. One call per run.
    """
    try:
        resp = await client.directory_roles.get()
    except Exception:  # noqa: BLE001
        return {}
    lookup: dict[str, str] = {}
    while resp is not None:
        for role in resp.value or []:
            template_id = getattr(role, "role_template_id", None) or getattr(
                role, "id", None
            )
            display_name = getattr(role, "display_name", None)
            if template_id and display_name:
                lookup[str(template_id)] = display_name
        next_link = getattr(resp, "odata_next_link", None)
        if not next_link:
            break
        try:
            resp = await client.directory_roles.with_url(next_link).get()
        except Exception:  # noqa: BLE001
            break
    return lookup
