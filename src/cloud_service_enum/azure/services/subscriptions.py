"""List subscriptions accessible to the credential (tenant-scoped)."""

from __future__ import annotations

from azure.mgmt.subscription.aio import SubscriptionClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, iter_async
from cloud_service_enum.core.models import ServiceResult


class SubscriptionsService(AzureService):
    service_name = "subscriptions"
    tenant_scoped = True

    async def collect_tenant(
        self, auth: AzureAuthenticator, result: ServiceResult
    ) -> None:
        async with SubscriptionClient(auth.credential()) as client:
            items = await iter_async(client.subscriptions.list())
        for s in items:
            result.resources.append(
                {
                    "kind": "subscription",
                    "id": getattr(s, "subscription_id", None),
                    "name": getattr(s, "display_name", None),
                    "state": getattr(s, "state", None),
                    "tenant_id": getattr(s, "tenant_id", None),
                }
            )
        result.cis_fields = {"subscription_count": len(items)}
