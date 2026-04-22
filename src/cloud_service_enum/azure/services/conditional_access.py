"""Conditional Access policies (Entra ID)."""

from __future__ import annotations

try:
    from msgraph import GraphServiceClient
except ImportError:  # pragma: no cover - optional
    GraphServiceClient = None  # type: ignore[assignment,misc]

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, _format_graph_error, _looks_like_graph_error
from cloud_service_enum.core.models import ServiceResult


class ConditionalAccessService(AzureService):
    service_name = "conditional_access"
    tenant_scoped = True

    async def collect_tenant(
        self, auth: AzureAuthenticator, result: ServiceResult
    ) -> None:
        if GraphServiceClient is None:
            result.errors.append("msgraph-sdk not installed")
            return
        client = GraphServiceClient(credentials=auth.credential(), scopes=["https://graph.microsoft.com/.default"])

        try:
            resp = await client.identity.conditional_access.policies.get()
        except Exception as exc:  # noqa: BLE001
            if _looks_like_graph_error(exc):
                result.errors.append(_format_graph_error(exc))
            else:
                result.errors.append(f"{type(exc).__name__}: {exc}")
            return

        policies = resp.value or [] if resp else []
        focused = self.is_focused_on()
        for p in policies:
            row = {
                "kind": "policy",
                "id": p.id,
                "name": p.display_name,
                "state": p.state,
                "created": p.created_date_time.isoformat() if p.created_date_time else None,
                "modified": p.modified_date_time.isoformat() if p.modified_date_time else None,
                "grant_controls": getattr(p.grant_controls, "built_in_controls", None) if p.grant_controls else None,
            }
            if focused:
                conditions = p.conditions
                row["policy_document"] = {
                    "displayName": p.display_name,
                    "state": p.state,
                    "conditions": {
                        "users": {
                            "include": getattr(conditions.users, "include_users", None)
                            if conditions and conditions.users
                            else None,
                            "exclude": getattr(conditions.users, "exclude_users", None)
                            if conditions and conditions.users
                            else None,
                            "include_groups": getattr(conditions.users, "include_groups", None)
                            if conditions and conditions.users
                            else None,
                            "include_roles": getattr(conditions.users, "include_roles", None)
                            if conditions and conditions.users
                            else None,
                        }
                        if conditions
                        else None,
                        "applications": {
                            "include": getattr(conditions.applications, "include_applications", None)
                            if conditions and conditions.applications
                            else None,
                            "exclude": getattr(conditions.applications, "exclude_applications", None)
                            if conditions and conditions.applications
                            else None,
                        }
                        if conditions
                        else None,
                        "client_app_types": getattr(conditions, "client_app_types", None)
                        if conditions
                        else None,
                        "locations": {
                            "include": getattr(conditions.locations, "include_locations", None)
                            if conditions and conditions.locations
                            else None,
                            "exclude": getattr(conditions.locations, "exclude_locations", None)
                            if conditions and conditions.locations
                            else None,
                        }
                        if conditions
                        else None,
                        "platforms": {
                            "include": getattr(conditions.platforms, "include_platforms", None)
                            if conditions and conditions.platforms
                            else None,
                            "exclude": getattr(conditions.platforms, "exclude_platforms", None)
                            if conditions and conditions.platforms
                            else None,
                        }
                        if conditions
                        else None,
                        "sign_in_risk_levels": getattr(conditions, "sign_in_risk_levels", None)
                        if conditions
                        else None,
                        "user_risk_levels": getattr(conditions, "user_risk_levels", None)
                        if conditions
                        else None,
                    },
                    "grant_controls": {
                        "operator": getattr(p.grant_controls, "operator", None),
                        "built_in_controls": getattr(p.grant_controls, "built_in_controls", None),
                        "authentication_strength": getattr(p.grant_controls, "authentication_strength", None),
                    }
                    if p.grant_controls
                    else None,
                    "session_controls": p.session_controls.__dict__
                    if p.session_controls
                    else None,
                }
            result.resources.append(row)
        result.cis_fields = {
            "policy_count": len(policies),
            "enabled_count": sum(1 for p in policies if p.state == "enabled"),
            "report_only_count": sum(1 for p in policies if p.state == "enabledForReportingButNotEnforced"),
        }
