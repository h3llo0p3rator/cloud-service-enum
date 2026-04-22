"""IAM service accounts, keys and custom roles."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list

try:
    from cloud_service_enum.data import load_lines

    _OWNER_PERMISSIONS = set(load_lines("gcp_owner_permissions.txt"))
except Exception:  # noqa: BLE001
    _OWNER_PERMISSIONS = set()

# Roles granted on a service-account resource that let another principal
# act as that SA. Token creator is the canonical privilege-escalation path;
# the others are flagged so auditors see the full picture.
_IMPERSONATION_ROLES: dict[str, str] = {
    "roles/iam.serviceAccountTokenCreator": "tokenCreator",
    "roles/iam.serviceAccountUser": "user",
    "roles/iam.workloadIdentityUser": "wifUser",
    "roles/iam.serviceAccountKeyAdmin": "keyAdmin",
    "roles/iam.serviceAccountAdmin": "saAdmin",
    "roles/iam.serviceAccounts.actAs": "actAs",
    "roles/owner": "owner",
    "roles/editor": "editor",
}


class IamService(GcpService):
    service_name = "iam"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import iam_admin_v1
        except ImportError:
            missing_sdk(result, "google-cloud-iam")
            return
        client = iam_admin_v1.IAMClient(credentials=credentials)
        accounts = safe_list(client.list_service_accounts(name=f"projects/{project_id}"))
        stale_keys = 0
        user_managed_keys = 0
        at_risk_accounts = 0
        for sa in accounts:
            sa_row: dict[str, Any] = {
                "kind": "service-account",
                "id": sa.unique_id,
                "name": sa.email,
                "display_name": sa.display_name,
                "project": project_id,
                "disabled": sa.disabled,
            }
            bindings = _fetch_sa_iam_policy(client, sa.name)
            if bindings is not None:
                impersonators = _summarize_impersonators(bindings)
                if impersonators["label"]:
                    sa_row["impersonators"] = impersonators["label"]
                    sa_row["role_bindings"] = bindings
                    at_risk_accounts += 1
                elif bindings:
                    sa_row["role_bindings"] = bindings
            result.resources.append(sa_row)
            try:
                keys = client.list_service_account_keys(name=sa.name)
                for k in keys.keys:
                    if k.key_type.name == "USER_MANAGED":
                        user_managed_keys += 1
                    if _stale(k.valid_after_time):
                        stale_keys += 1
                    result.resources.append(
                        {
                            "kind": "service-account-key",
                            "id": k.name,
                            "service_account": sa.email,
                            "project": project_id,
                            "valid_after": k.valid_after_time.isoformat() if k.valid_after_time else None,
                            "valid_before": k.valid_before_time.isoformat() if k.valid_before_time else None,
                            "key_type": k.key_type.name,
                            "key_origin": k.key_origin.name,
                        }
                    )
            except Exception:  # noqa: BLE001
                pass
        focused = self.is_focused_on()
        roles = safe_list(client.list_roles(request={"parent": f"projects/{project_id}"}))
        for r in roles:
            row = {
                "kind": "custom-role",
                "id": r.name,
                "title": r.title,
                "project": project_id,
                "stage": r.stage.name,
                "included_permissions": list(r.included_permissions),
                "dangerous_permission_count": sum(
                    1 for p in r.included_permissions if p in _OWNER_PERMISSIONS
                ),
            }
            if focused:
                row["policy_document"] = {
                    "name": r.name,
                    "title": r.title,
                    "description": r.description,
                    "stage": r.stage.name,
                    "includedPermissions": list(r.included_permissions),
                }
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "service_account_count": len(accounts),
            "user_managed_keys": user_managed_keys,
            "stale_keys": stale_keys,
            "custom_role_count": len(roles),
            "impersonable_service_accounts": at_risk_accounts,
        }


def _fetch_sa_iam_policy(client: Any, sa_resource: str) -> list[dict[str, Any]] | None:
    """Return the IAM policy bindings on a service-account resource.

    ``None`` means the call failed (e.g. ``iam.serviceAccounts.getIamPolicy``
    denied) and the caller should treat the field as unknown rather than empty.
    """
    try:
        policy = client.get_iam_policy(resource=sa_resource)
    except Exception:  # noqa: BLE001
        return None
    return [
        {"role": b.role, "members": list(b.members)}
        for b in policy.bindings
    ]


def _summarize_impersonators(bindings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a compact ``tokenCreator(2)+user(1)`` label for the table column."""
    counts: dict[str, int] = {}
    for b in bindings:
        short = _IMPERSONATION_ROLES.get(b["role"])
        if not short:
            continue
        counts[short] = counts.get(short, 0) + len(b["members"])
    priority = list(dict.fromkeys(_IMPERSONATION_ROLES.values()))
    parts = [f"{name}({counts[name]})" for name in priority if counts.get(name)]
    return {"label": "+".join(parts), "counts": counts}


def _stale(valid_after: Any, threshold_days: int = 90) -> bool:
    if not valid_after:
        return False
    try:
        return (datetime.now(timezone.utc) - valid_after).days > threshold_days
    except Exception:  # noqa: BLE001
        return False
