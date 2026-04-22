"""Binary Authorization policy and attestors."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, format_gcp_error, missing_sdk, safe_list


class BinaryAuthorizationService(GcpService):
    service_name = "binaryauthorization"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import binaryauthorization_v1 as ba
        except ImportError:
            missing_sdk(result, "google-cloud-binary-authorization")
            return
        client = ba.BinauthzManagementServiceV1Client(credentials=credentials)
        try:
            policy = client.get_policy(name=f"projects/{project_id}/policy")
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"[{project_id}] policy: {format_gcp_error(exc)}")
            return
        result.resources.append(
            {
                "kind": "policy",
                "id": policy.name,
                "project": project_id,
                "default_admission_rule": policy.default_admission_rule.enforcement_mode.name,
                "global_policy_evaluation": policy.global_policy_evaluation_mode.name,
                "admission_whitelist_patterns": [
                    w.name_pattern for w in policy.admission_whitelist_patterns
                ],
                "cluster_admission_rules": dict(policy.cluster_admission_rules),
            }
        )
        attestors = safe_list(client.list_attestors(parent=f"projects/{project_id}"))
        for a in attestors:
            result.resources.append(
                {
                    "kind": "attestor",
                    "id": a.name,
                    "name": a.name.split("/")[-1],
                    "project": project_id,
                    "description": a.description,
                }
            )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "attestor_count": len(attestors),
            "default_enforcement": policy.default_admission_rule.enforcement_mode.name,
        }
