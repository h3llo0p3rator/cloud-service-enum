"""Policy compliance summary via Policy Insights."""

from __future__ import annotations

from azure.core.exceptions import HttpResponseError
from azure.mgmt.policyinsights.aio import PolicyInsightsClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, _format_http_error, iter_async
from cloud_service_enum.core.models import ServiceResult


class PolicyInsightsService(AzureService):
    service_name = "policyinsights"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        async with PolicyInsightsClient(auth.credential(), subscription_id) as client:
            try:
                states = await iter_async(
                    client.policy_states.list_query_results_for_subscription(
                        policy_states_resource="latest", subscription_id=subscription_id
                    )
                )
            except HttpResponseError as exc:
                result.errors.append(f"[{subscription_id}] {_format_http_error(exc)}")
                return
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"[{subscription_id}] {type(exc).__name__}: {exc}")
                return
        compliant = sum(1 for s in states if s.compliance_state == "Compliant")
        non_compliant = sum(1 for s in states if s.compliance_state == "NonCompliant")
        result.resources.append(
            {
                "kind": "compliance-summary",
                "id": subscription_id,
                "subscription": subscription_id,
                "total": len(states),
                "compliant": compliant,
                "non_compliant": non_compliant,
            }
        )
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "compliance_total": len(states),
            "non_compliant": non_compliant,
        }
