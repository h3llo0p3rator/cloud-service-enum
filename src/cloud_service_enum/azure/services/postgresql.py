"""Azure Database for PostgreSQL (flexible servers)."""

from __future__ import annotations

try:
    from azure.mgmt.rdbms.postgresql_flexibleservers.aio import PostgreSQLManagementClient
except ImportError:  # pragma: no cover - optional
    PostgreSQLManagementClient = None  # type: ignore[assignment,misc]

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class PostgresqlService(AzureService):
    service_name = "postgresql"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        if PostgreSQLManagementClient is None:
            result.errors.append("azure-mgmt-rdbms not installed")
            return
        focused = self.is_focused_on()
        async with PostgreSQLManagementClient(auth.credential(), subscription_id) as client:
            servers = await iter_async(client.servers.list())
            for s in servers:
                row = {
                    "kind": "server",
                    "id": s.id,
                    "name": s.name,
                    "location": s.location,
                    "subscription": subscription_id,
                    "version": s.version,
                    "administrator_login": getattr(s, "administrator_login", None),
                    "public_network_access": getattr(s.network, "public_network_access", None) if s.network else None,
                    "ssl_enforcement": getattr(s, "ssl_enforcement", None),
                    "data_encryption_type": getattr(s.data_encryption, "type", None) if s.data_encryption else None,
                    "high_availability_mode": s.high_availability.mode if s.high_availability else None,
                    "backup_retention_days": s.backup.backup_retention_days if s.backup else None,
                }
                attach_identity(row, s)
                if focused:
                    rg = s.id.split("/")[4]
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
                        configs = await iter_async(
                            client.configurations.list_by_server(rg, s.name)
                        )
                        notable = {
                            c.name: c.value
                            for c in configs
                            if c.name
                            in {
                                "log_checkpoints",
                                "log_connections",
                                "log_disconnections",
                                "log_retention_days",
                                "connection_throttling",
                                "log_min_duration_statement",
                                "azure.extensions",
                                "require_secure_transport",
                            }
                        }
                        if notable:
                            row["env_vars"] = notable
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "server_count": len(servers),
        }
