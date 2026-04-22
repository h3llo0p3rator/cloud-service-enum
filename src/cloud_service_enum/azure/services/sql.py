"""Azure SQL servers, databases and auditing."""

from __future__ import annotations

from azure.mgmt.sql.aio import SqlManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class SqlService(AzureService):
    service_name = "sql"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        async with SqlManagementClient(auth.credential(), subscription_id) as client:
            servers = await iter_async(client.servers.list())
            for s in servers:
                rg = s.id.split("/")[4]
                dbs = await iter_async(client.databases.list_by_server(rg, s.name))
                tde_info = []
                for db in dbs:
                    if db.name == "master":
                        continue
                    try:
                        tde = await client.transparent_data_encryptions.get(rg, s.name, db.name, "current")
                        tde_info.append((db.name, tde.state))
                    except Exception:  # noqa: BLE001
                        tde_info.append((db.name, None))
                    result.resources.append(
                        {
                            "kind": "sql-database",
                            "id": db.id,
                            "name": db.name,
                            "server": s.name,
                            "location": db.location,
                            "subscription": subscription_id,
                            "sku": db.sku.name if db.sku else None,
                            "status": db.status,
                            "zone_redundant": db.zone_redundant,
                            "tde_state": dict(tde_info).get(db.name),
                        }
                    )
                ad_admins = await iter_async(client.server_azure_ad_administrators.list_by_server(rg, s.name))
                row = {
                    "kind": "sql-server",
                    "id": s.id,
                    "name": s.name,
                    "location": s.location,
                    "subscription": subscription_id,
                    "version": s.version,
                    "minimal_tls_version": s.minimal_tls_version,
                    "public_network_access": s.public_network_access,
                    "administrator_login": s.administrator_login,
                    "ad_admins": [a.login for a in ad_admins],
                    "database_count": len(dbs),
                }
                attach_identity(row, s)
                if focused:
                    try:
                        firewall = await iter_async(
                            client.firewall_rules.list_by_server(rg, s.name)
                        )
                        row["firewall_rules"] = [
                            {
                                "name": f.name,
                                "start_ip": f.start_ip_address,
                                "end_ip": f.end_ip_address,
                            }
                            for f in firewall
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        audit = await client.server_blob_auditing_policies.get(rg, s.name)
                        if audit:
                            row["auditing"] = {
                                "state": audit.state,
                                "storage_endpoint": audit.storage_endpoint,
                                "retention_days": audit.retention_days,
                            }
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "server_count": sum(1 for r in result.resources if r.get("kind") == "sql-server"),
            "servers_public": sum(
                1
                for r in result.resources
                if r.get("kind") == "sql-server" and r.get("public_network_access") == "Enabled"
            ),
        }
