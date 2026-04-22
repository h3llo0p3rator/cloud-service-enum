"""Policy assignments (applied guardrails)."""

from __future__ import annotations

from azure.mgmt.resource.policy.aio import PolicyClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class PolicyService(AzureService):
    service_name = "policy"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with PolicyClient(auth.credential(), subscription_id) as client:
            assignments = await iter_async(client.policy_assignments.list())
            for a in assignments:
                row = {
                    "kind": "policy-assignment",
                    "id": a.id,
                    "name": a.name,
                    "subscription": subscription_id,
                    "display_name": a.display_name,
                    "enforcement_mode": a.enforcement_mode,
                    "policy_definition_id": a.policy_definition_id,
                    "scope": a.scope,
                }
                if focused:
                    row["policy_document"] = {
                        "displayName": a.display_name,
                        "description": a.description,
                        "policyDefinitionId": a.policy_definition_id,
                        "parameters": (
                            {k: v.as_dict() for k, v in (a.parameters or {}).items()}
                            if a.parameters
                            else {}
                        ),
                        "nonComplianceMessages": [
                            m.as_dict() for m in (a.non_compliance_messages or [])
                        ],
                        "notScopes": a.not_scopes,
                    }
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "assignment_count": len(assignments),
        }
