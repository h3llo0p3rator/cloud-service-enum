"""Microsoft Sentinel (via Security Insights on log-analytics workspaces)."""

from __future__ import annotations

from azure.mgmt.loganalytics.aio import LogAnalyticsManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult

try:
    from azure.mgmt.securityinsight.aio import SecurityInsights
except ImportError:  # pragma: no cover - optional
    SecurityInsights = None  # type: ignore[assignment,misc]


class SentinelService(AzureService):
    service_name = "sentinel"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        async with LogAnalyticsManagementClient(auth.credential(), subscription_id) as la_client:
            workspaces = await iter_async(la_client.workspaces.list())

        if SecurityInsights is None:
            result.errors.append("azure-mgmt-securityinsight not installed")
            result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
                "workspace_count": len(workspaces),
                "sentinel_workspaces": 0,
            }
            return

        focused = self.is_focused_on()
        sentinel_workspaces = 0
        async with SecurityInsights(auth.credential(), subscription_id) as si:
            for w in workspaces:
                rg = w.id.split("/")[4]
                try:
                    onboards = await iter_async(si.sentinel_onboarding_states.list(rg, w.name))
                except Exception:  # noqa: BLE001
                    onboards = []
                if not onboards:
                    continue
                sentinel_workspaces += 1
                try:
                    incidents = await iter_async(si.incidents.list(rg, w.name))
                except Exception:  # noqa: BLE001
                    incidents = []
                row = {
                    "kind": "workspace",
                    "id": w.id,
                    "name": w.name,
                    "subscription": subscription_id,
                    "onboarding_states": len(onboards),
                    "incidents": len(incidents),
                }
                if focused:
                    try:
                        rules = await iter_async(si.alert_rules.list(rg, w.name))
                        row["alert_rules"] = [
                            {
                                "name": r.display_name,
                                "kind": r.kind,
                                "enabled": getattr(r, "enabled", None),
                                "severity": getattr(r, "severity", None),
                                "query": (
                                    getattr(r, "query", None)
                                    if getattr(r, "kind", "") == "Scheduled"
                                    else None
                                ),
                            }
                            for r in rules
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        connectors = await iter_async(si.data_connectors.list(rg, w.name))
                        row["data_connectors"] = [
                            {"name": c.name, "kind": c.kind} for c in connectors
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "workspace_count": len(workspaces),
            "sentinel_workspaces": sentinel_workspaces,
        }
