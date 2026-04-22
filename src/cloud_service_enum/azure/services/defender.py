"""Microsoft Defender for Cloud posture and pricing tiers."""

from __future__ import annotations

from azure.mgmt.security.aio import SecurityCenter

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class DefenderService(AzureService):
    service_name = "defender"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        async with SecurityCenter(auth.credential(), subscription_id) as client:
            pricings: list = []
            try:
                scope = f"/subscriptions/{subscription_id}"
                resp = await client.pricings.list(scope_id=scope)
                pricings = list(getattr(resp, "value", None) or [])
            except Exception:  # noqa: BLE001
                pass
            auto_provision = []
            try:
                auto_provision = await iter_async(client.auto_provisioning_settings.list())
            except Exception:  # noqa: BLE001
                pass
            contacts = []
            try:
                contacts = await iter_async(client.security_contacts.list())
            except Exception:  # noqa: BLE001
                pass
        for p in pricings:
            result.resources.append(
                {
                    "kind": "pricing",
                    "id": p.id,
                    "name": p.name,
                    "subscription": subscription_id,
                    "pricing_tier": p.pricing_tier,
                    "free_trial_remaining_time": str(p.free_trial_remaining_time) if hasattr(p, "free_trial_remaining_time") else None,
                }
            )
        for ap in auto_provision:
            result.resources.append(
                {
                    "kind": "auto-provision",
                    "id": ap.id,
                    "name": ap.name,
                    "subscription": subscription_id,
                    "auto_provision": ap.auto_provision,
                }
            )
        for c in contacts:
            result.resources.append(
                {
                    "kind": "security-contact",
                    "id": c.id,
                    "name": c.name,
                    "subscription": subscription_id,
                    "emails": getattr(c, "emails", None),
                    "phone": c.phone,
                    "alert_notifications": getattr(c, "alert_notifications", None),
                }
            )
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "plans_with_standard_tier": sum(1 for p in pricings if p.pricing_tier == "Standard"),
            "plans_with_free_tier": sum(1 for p in pricings if p.pricing_tier == "Free"),
            "has_security_contact": bool(contacts),
        }
