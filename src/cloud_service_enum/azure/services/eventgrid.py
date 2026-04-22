"""Event Grid topics and domains."""

from __future__ import annotations

from azure.mgmt.eventgrid.aio import EventGridManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class EventGridService(AzureService):
    service_name = "eventgrid"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        from cloud_service_enum.core.secrets import mask

        focused = self.is_focused_on()
        async with EventGridManagementClient(auth.credential(), subscription_id) as client:
            topics = await iter_async(client.topics.list_by_subscription())
            domains = await iter_async(client.domains.list_by_subscription())
            for t in topics:
                row = {
                    "kind": "topic",
                    "id": t.id,
                    "name": t.name,
                    "location": t.location,
                    "subscription": subscription_id,
                    "public_network_access": t.public_network_access,
                    "local_auth_disabled": t.disable_local_auth,
                    "input_schema": t.input_schema,
                    "endpoint": t.endpoint,
                }
                attach_identity(row, t)
                if focused:
                    rg = t.id.split("/")[4]
                    try:
                        keys = await client.topics.list_shared_access_keys(rg, t.name)
                        row["env_vars"] = {
                            "key1": mask(keys.key1 or ""),
                            "key2": mask(keys.key2 or ""),
                        }
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
            for d in domains:
                drow = {
                    "kind": "domain",
                    "id": d.id,
                    "name": d.name,
                    "location": d.location,
                    "subscription": subscription_id,
                    "public_network_access": d.public_network_access,
                    "local_auth_disabled": d.disable_local_auth,
                }
                attach_identity(drow, d)
                if focused:
                    rg = d.id.split("/")[4]
                    try:
                        keys = await client.domains.list_shared_access_keys(rg, d.name)
                        drow["env_vars"] = {
                            "key1": mask(keys.key1 or ""),
                            "key2": mask(keys.key2 or ""),
                        }
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(drow)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "topic_count": len(topics),
            "domain_count": len(domains),
        }
