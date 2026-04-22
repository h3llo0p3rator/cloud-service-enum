"""Security Command Center (SCC) sources and findings."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class SecurityCenterService(GcpService):
    service_name = "securitycenter"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import securitycenter
        except ImportError:
            missing_sdk(result, "google-cloud-securitycenter")
            return
        client = securitycenter.SecurityCenterClient(credentials=credentials)
        parent = f"projects/{project_id}"
        sources = safe_list(client.list_sources(request={"parent": parent}))
        for s in sources:
            result.resources.append(
                {
                    "kind": "source",
                    "id": s.name,
                    "project": project_id,
                    "display_name": s.display_name,
                    "description": s.description,
                }
            )
        try:
            findings = client.list_findings(
                request={
                    "parent": f"{parent}/sources/-",
                    "filter": "state=\"ACTIVE\"",
                    "page_size": 1000,
                }
            )
            finding_list = safe_list(findings)
        except Exception:  # noqa: BLE001
            finding_list = []
        by_severity: dict[str, int] = {}
        focused = self.is_focused_on()
        for f in finding_list:
            sev = f.finding.severity.name if f.finding else "UNKNOWN"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            if focused and f.finding:
                result.resources.append(
                    {
                        "kind": "finding",
                        "id": f.finding.name,
                        "category": f.finding.category,
                        "severity": sev,
                        "state": f.finding.state.name,
                        "resource_name": f.finding.resource_name,
                        "event_time": f.finding.event_time.isoformat()
                        if f.finding.event_time
                        else None,
                        "external_uri": f.finding.external_uri,
                        "description": f.finding.description,
                    }
                )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "source_count": len(sources),
            "active_findings": len(finding_list),
            "findings_by_severity": by_severity,
        }
