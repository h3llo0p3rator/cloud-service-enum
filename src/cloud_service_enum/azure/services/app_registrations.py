"""App Registrations — password/key/federated credentials + dangerous scopes.

Expired / near-expiring secrets and dangerous delegated + application
permissions are the two audit signals that matter the most here.
Microsoft Graph never returns the credential plaintext; this enumerator
ships the metadata (hint, dates, display name) so the secret hygiene
posture is auditable.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from msgraph import GraphServiceClient
except ImportError:  # pragma: no cover - optional
    GraphServiceClient = None  # type: ignore[assignment,misc]

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService
from cloud_service_enum.core.models import ServiceResult

# Application / delegated permissions commonly abused for tenant-wide
# privilege escalation. Matched case-insensitively on the permission
# "value" string returned by Graph in requiredResourceAccess.
_DANGEROUS_PERMISSIONS: frozenset[str] = frozenset(
    {
        "application.readwrite.all",
        "application.readwrite.ownedby",
        "approleassignment.readwrite.all",
        "directory.readwrite.all",
        "rolemanagement.readwrite.directory",
        "user.readwrite.all",
        "group.readwrite.all",
        "groupmember.readwrite.all",
        "privilegedaccess.readwrite.azuread",
        "privilegedaccess.readwrite.azureadgroup",
        "privilegedaccess.readwrite.azureresources",
        "mail.readwrite",
        "mail.send",
        "files.readwrite.all",
        "sites.fullcontrol.all",
        "sites.readwrite.all",
    }
)

# Graph app id → friendly label so the "resource_app" column in the
# display shows something more useful than a guid.
_KNOWN_RESOURCE_APPS: dict[str, str] = {
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "00000002-0000-0000-c000-000000000000": "Azure AD Graph (legacy)",
    "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online",
    "797f4846-ba00-4fd7-ba43-dac1f8f63013": "Azure Service Management",
}


class AppRegistrationsService(AzureService):
    service_name = "app-registration"
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
        apps = await _drain_applications(client)

        focused = self.is_focused_on()
        expired_total = 0
        active_total = 0
        dangerous_total = 0
        for app in apps:
            row = _application_row(app)
            if focused and app.id:
                row["federated_credentials"] = await _federated_credentials(
                    client, app.id
                )
            expired_total += row.get("secret_count_expired", 0)
            active_total += row.get("secret_count_active", 0)
            if row.get("dangerous_scopes"):
                dangerous_total += 1
            result.resources.append(row)

        result.cis_fields = {
            "application_count": len(apps),
            "secrets_expired": expired_total,
            "secrets_active": active_total,
            "apps_with_dangerous_scopes": dangerous_total,
        }


async def _drain_applications(client: Any) -> list[Any]:
    resp = await client.applications.get()
    out: list[Any] = []
    while resp is not None:
        out.extend(resp.value or [])
        next_link = getattr(resp, "odata_next_link", None)
        if not next_link:
            break
        resp = await client.applications.with_url(next_link).get()
    return out


def _application_row(app: Any) -> dict[str, Any]:
    passwords = [_password_entry(p) for p in app.password_credentials or []]
    keys = [_key_entry(k) for k in app.key_credentials or []]
    required = _required_resource_access(app.required_resource_access or [])
    dangerous = sorted(
        {
            access["value"]
            for entry in required
            for access in entry.get("resource_access", [])
            if access.get("value")
            and access["value"].lower() in _DANGEROUS_PERMISSIONS
        }
    )
    row: dict[str, Any] = {
        "kind": "app-registration",
        "id": app.id,
        "app_id": app.app_id,
        "name": app.display_name,
        "sign_in_audience": app.sign_in_audience,
        "publisher_domain": app.publisher_domain,
        "created": app.created_date_time.isoformat() if app.created_date_time else None,
        "password_credentials": passwords,
        "key_credentials": keys,
        "secret_count_expired": sum(1 for p in passwords if p.get("expired")),
        "secret_count_active": sum(1 for p in passwords if not p.get("expired")),
    }
    if required:
        row["required_resource_access"] = required
    if dangerous:
        row["dangerous_scopes"] = list(dangerous)
    return row


def _password_entry(cred: Any) -> dict[str, Any]:
    end = cred.end_date_time
    start = cred.start_date_time
    now = datetime.now(timezone.utc)
    expired = bool(end and end < now)
    expires_in_days = None
    if end:
        expires_in_days = int((end - now) / timedelta(days=1))
    return {
        "key_id": cred.key_id,
        "display_name": cred.display_name,
        "hint": cred.hint,
        "start_date": start.isoformat() if start else None,
        "end_date": end.isoformat() if end else None,
        "expired": expired,
        "expires_in_days": expires_in_days,
    }


def _key_entry(cred: Any) -> dict[str, Any]:
    end = cred.end_date_time
    start = cred.start_date_time
    now = datetime.now(timezone.utc)
    expired = bool(end and end < now)
    return {
        "key_id": cred.key_id,
        "display_name": cred.display_name,
        "type": cred.type,
        "usage": cred.usage,
        "start_date": start.isoformat() if start else None,
        "end_date": end.isoformat() if end else None,
        "expired": expired,
    }


def _required_resource_access(entries: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in entries:
        resource_app_id = getattr(entry, "resource_app_id", None)
        resource_accesses = []
        for access in getattr(entry, "resource_access", None) or []:
            access_id = getattr(access, "id", None)
            access_type = getattr(access, "type", None)
            resource_accesses.append(
                {
                    "id": str(access_id) if access_id else None,
                    "type": access_type,
                    # We only have the guid here; the "value" string lives
                    # on the service principal, not on the application, so
                    # we surface the guid and let the auditor resolve.
                    "value": _lookup_known_scope(resource_app_id, access_id),
                }
            )
        out.append(
            {
                "resource_app_id": resource_app_id,
                "resource_app_name": _KNOWN_RESOURCE_APPS.get(
                    resource_app_id or "", None
                ),
                "resource_access": resource_accesses,
            }
        )
    return out


def _lookup_known_scope(resource_app_id: str | None, access_id: Any) -> str | None:
    """Resolve well-known Graph permission guids to their scope value.

    Reduces the ``dangerous_scopes`` list to the handful of permissions
    the lab has actually hit without needing to talk to the service
    principal endpoint.
    """
    if not access_id or resource_app_id != "00000003-0000-0000-c000-000000000000":
        return None
    return _GRAPH_PERMISSION_GUID_TO_SCOPE.get(str(access_id).lower())


# Hand-maintained map of commonly-abused Microsoft Graph permission
# guids to their scope value strings. Extending this list only affects
# the ``dangerous_scopes`` detection; every permission still lands in
# ``required_resource_access`` verbatim.
_GRAPH_PERMISSION_GUID_TO_SCOPE: dict[str, str] = {
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "18a4783c-866b-4cc7-a460-3d5e5662c884": "Application.ReadWrite.OwnedBy",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "dbaae8cf-10b5-4b86-a4a1-f871c94c6695": "GroupMember.ReadWrite.All",
    "41202f2c-f7ab-45be-b001-85c9728b9d69": "PrivilegedAccess.ReadWrite.AzureAD",
    "32531c59-1f32-461f-b8df-6f8a3b89f73b": "PrivilegedAccess.ReadWrite.AzureADGroup",
    "a84a9652-ffd3-496e-a991-22ba5529156a": "PrivilegedAccess.ReadWrite.AzureResources",
    "024d486e-b451-40bb-833d-3e66d98c5c73": "Mail.ReadWrite",
    "b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
    "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
    "a82116e5-55eb-4c41-a434-62fe8a61c773": "Sites.FullControl.All",
    "9492366f-7969-46a4-8d15-ed1a20078fff": "Sites.ReadWrite.All",
}


async def _federated_credentials(client: Any, app_id: str) -> list[dict[str, Any]]:
    try:
        resp = await (
            client.applications.by_application_id(app_id)
            .federated_identity_credentials.get()
        )
    except Exception:  # noqa: BLE001
        return []
    items = getattr(resp, "value", None) or []
    return [
        {
            "name": getattr(c, "name", None),
            "issuer": getattr(c, "issuer", None),
            "subject": getattr(c, "subject", None),
            "audiences": list(getattr(c, "audiences", None) or []),
        }
        for c in items
    ]
