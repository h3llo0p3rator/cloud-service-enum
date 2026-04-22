"""Privileged Identity Management (PIM) role eligibility and assignments.

Uses Microsoft Graph roleManagement/directory endpoints. Surfaces the
set of role-eligible principals and any active privileged assignments.
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


class PimService(AzureService):
    service_name = "pim"
    tenant_scoped = True

    async def collect_tenant(
        self, auth: AzureAuthenticator, result: ServiceResult
    ) -> None:
        if GraphServiceClient is None:
            result.errors.append("msgraph-sdk not installed")
            return
        client = GraphServiceClient(credentials=auth.credential(), scopes=["https://graph.microsoft.com/.default"])

        eligibility = await _drain(client.role_management.directory.role_eligibility_schedule_instances)
        active = await _drain(client.role_management.directory.role_assignment_schedule_instances)

        for e in eligibility:
            result.resources.append(
                {
                    "kind": "eligibility",
                    "id": e.id,
                    "principal_id": e.principal_id,
                    "role_definition_id": e.role_definition_id,
                    "directory_scope_id": e.directory_scope_id,
                    "start": e.start_date_time.isoformat() if e.start_date_time else None,
                    "end": e.end_date_time.isoformat() if e.end_date_time else None,
                }
            )
        for a in active:
            result.resources.append(
                {
                    "kind": "active-assignment",
                    "id": a.id,
                    "principal_id": a.principal_id,
                    "role_definition_id": a.role_definition_id,
                    "assignment_type": a.assignment_type,
                    "member_type": a.member_type,
                }
            )
        result.cis_fields = {
            "eligible_count": len(eligibility),
            "active_count": len(active),
        }


async def _drain(endpoint: Any) -> list[Any]:
    try:
        resp = await endpoint.get()
    except Exception:  # noqa: BLE001
        return []
    out: list[Any] = []
    while resp is not None:
        out.extend(resp.value or [])
        next_link = getattr(resp, "odata_next_link", None)
        if not next_link:
            break
        try:
            resp = await endpoint.with_url(next_link).get()
        except Exception:  # noqa: BLE001
            break
    return out
