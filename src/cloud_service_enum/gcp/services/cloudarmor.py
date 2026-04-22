"""Cloud Armor security policies."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class CloudArmorService(GcpService):
    service_name = "cloudarmor"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import compute_v1
        except ImportError:
            missing_sdk(result, "google-cloud-compute")
            return
        client = compute_v1.SecurityPoliciesClient(credentials=credentials)
        policies = safe_list(client.list(project=project_id))
        focused = self.is_focused_on()
        for p in policies:
            row = {
                "kind": "policy",
                "id": str(p.id),
                "name": p.name,
                "project": project_id,
                "type": p.type_,
                "description": p.description,
                "rule_count": len(p.rules),
                "adaptive_protection": bool(
                    p.adaptive_protection_config
                    and p.adaptive_protection_config.layer7_ddos_defense_config
                    and p.adaptive_protection_config.layer7_ddos_defense_config.enable
                ),
            }
            if focused:
                row["firewall_rules"] = [
                    {
                        "priority": r.priority,
                        "action": r.action,
                        "description": r.description or "-",
                        "src": ", ".join(r.match.config.src_ip_ranges or [])
                        if r.match and r.match.config
                        else "-",
                        "expression": (
                            r.match.expr.expression
                            if r.match and r.match.expr
                            else "-"
                        ),
                        "preview": r.preview,
                    }
                    for r in p.rules or []
                ]
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "policy_count": len(policies),
            "policies_with_adaptive_protection": sum(
                1
                for p in policies
                if p.adaptive_protection_config
                and p.adaptive_protection_config.layer7_ddos_defense_config
                and p.adaptive_protection_config.layer7_ddos_defense_config.enable
            ),
        }
