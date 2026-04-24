"""Managed identities — user-assigned MIs, role assignments, federated creds.

User-assigned MIs are first-class security principals: the interesting
auditable fields are ``principal_id`` (for cross-referencing with RBAC),
``federated_identity_credentials`` (for external IdP trust), and the
roles they hold across subscriptions.
"""

from __future__ import annotations

from typing import Any

from azure.mgmt.authorization.aio import AuthorizationManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class ManagedIdentityService(AzureService):
    service_name = "managed-identity"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        try:
            from azure.mgmt.msi.aio import ManagedServiceIdentityClient
        except ImportError:
            result.errors.append(
                "azure-mgmt-msi is not installed; install the [azure] extra"
            )
            return

        focused = self.is_focused_on()
        async with ManagedServiceIdentityClient(
            auth.credential(), subscription_id
        ) as msi, AuthorizationManagementClient(
            auth.credential(), subscription_id
        ) as authz:
            identities = await iter_async(
                msi.user_assigned_identities.list_by_subscription()
            )
            for ident in identities:
                rg = (ident.id or "").split("/")[4] if ident.id else None
                row = _identity_row(ident, subscription_id, rg)
                if focused:
                    if ident.principal_id:
                        row["role_bindings"] = await _role_bindings(
                            authz, ident.id, ident.principal_id
                        )
                    if rg and ident.name:
                        row["federated_credentials"] = await _federated_credentials(
                            msi, rg, ident.name
                        )
                result.resources.append(row)

        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "user_assigned_identity_count": len(identities),
        }


def _identity_row(
    ident: Any, subscription_id: str, rg: str | None
) -> dict[str, Any]:
    return {
        "kind": "user-assigned-mi",
        "id": ident.id,
        "name": ident.name,
        "resource_group": rg,
        "location": getattr(ident, "location", None),
        "subscription": subscription_id,
        "principal_id": getattr(ident, "principal_id", None),
        "client_id": getattr(ident, "client_id", None),
        "tenant_id": getattr(ident, "tenant_id", None),
        "tags": getattr(ident, "tags", None) or {},
    }


async def _role_bindings(
    authz: Any, scope: str, principal_id: str
) -> list[dict[str, Any]]:
    """Return every role assignment whose principal matches ``principal_id``.

    Uses ``list_for_scope`` on the identity's own resource id so Azure
    returns assignments inherited from parent scopes too.
    """
    try:
        assignments = await iter_async(
            authz.role_assignments.list_for_scope(
                scope=scope,
                filter=f"principalId eq '{principal_id}'",
            )
        )
    except Exception:  # noqa: BLE001
        return []
    return [
        {
            "id": a.id,
            "scope": a.scope,
            "role_definition_id": a.role_definition_id,
            "principal_id": a.principal_id,
            "principal_type": getattr(a, "principal_type", None),
        }
        for a in assignments
    ]


async def _federated_credentials(
    msi: Any, rg: str, identity_name: str
) -> list[dict[str, Any]]:
    try:
        creds = await iter_async(
            msi.federated_identity_credentials.list(rg, identity_name)
        )
    except Exception:  # noqa: BLE001
        return []
    return [
        {
            "name": c.name,
            "issuer": getattr(c, "issuer", None),
            "subject": getattr(c, "subject", None),
            "audiences": list(getattr(c, "audiences", None) or []),
            "claims_matching_expression": getattr(
                c, "claims_matching_expression", None
            ),
        }
        for c in creds
    ]
