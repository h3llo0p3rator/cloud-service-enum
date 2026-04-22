"""RBAC role assignments and custom roles."""

from __future__ import annotations

from azure.mgmt.authorization.aio import AuthorizationManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class RbacService(AzureService):
    service_name = "rbac"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        async with AuthorizationManagementClient(auth.credential(), subscription_id) as client:
            assignments = await iter_async(
                client.role_assignments.list_for_subscription()
            )
            defs = await iter_async(
                client.role_definitions.list(scope=f"/subscriptions/{subscription_id}")
            )
        for a in assignments:
            result.resources.append(
                {
                    "kind": "role-assignment",
                    "id": a.id,
                    "scope": a.scope,
                    "role_definition_id": a.role_definition_id,
                    "principal_id": a.principal_id,
                    "principal_type": a.principal_type,
                    "subscription": subscription_id,
                }
            )
        customs = [d for d in defs if d.role_type == "CustomRole"]
        focused = self.is_focused_on()
        for d in customs:
            row = {
                "kind": "custom-role",
                "id": d.id,
                "name": d.role_name,
                "subscription": subscription_id,
                "permissions": [p.as_dict() for p in (d.permissions or [])],
                "assignable_scopes": d.assignable_scopes,
            }
            if focused:
                row["policy_document"] = {
                    "name": d.role_name,
                    "description": d.description,
                    "permissions": [p.as_dict() for p in (d.permissions or [])],
                    "assignableScopes": d.assignable_scopes,
                }
            result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "assignment_count": len(assignments),
            "custom_role_count": len(customs),
            "owner_assignments": sum(
                1
                for a in assignments
                if isinstance(a.role_definition_id, str) and a.role_definition_id.endswith("8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
            ),
        }
