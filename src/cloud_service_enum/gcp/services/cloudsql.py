"""Cloud SQL instances."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk


class CloudSqlService(GcpService):
    service_name = "cloudsql"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from googleapiclient import discovery
        except ImportError:
            missing_sdk(result, "google-api-python-client")
            return
        api = discovery.build("sqladmin", "v1", credentials=credentials, cache_discovery=False)
        resp = api.instances().list(project=project_id).execute()
        items = resp.get("items") or []
        public_instances = 0
        no_ssl = 0
        focused = self.is_focused_on()
        for i in items:
            settings = i.get("settings") or {}
            ip_config = settings.get("ipConfiguration") or {}
            backup_config = settings.get("backupConfiguration") or {}
            if ip_config.get("ipv4Enabled"):
                public_instances += 1
            if ip_config.get("requireSsl") is False:
                no_ssl += 1
            row = {
                "kind": "instance",
                "id": i["name"],
                "name": i["name"],
                "project": project_id,
                "region": i.get("region"),
                "database_version": i.get("databaseVersion"),
                "tier": settings.get("tier"),
                "ipv4_enabled": ip_config.get("ipv4Enabled", False),
                "ssl_mode": ip_config.get("sslMode") or ip_config.get("requireSsl"),
                "authorized_networks": ip_config.get("authorizedNetworks", []),
                "backup_enabled": backup_config.get("enabled", False),
                "binary_log_enabled": backup_config.get("binaryLogEnabled"),
                "pitr_enabled": backup_config.get("pointInTimeRecoveryEnabled"),
                "availability_type": settings.get("availabilityType"),
                "state": i.get("state"),
            }
            if focused:
                row["firewall_rules"] = [
                    {
                        "name": net.get("name") or "(unnamed)",
                        "value": net.get("value"),
                        "expirationTime": net.get("expirationTime"),
                    }
                    for net in ip_config.get("authorizedNetworks", [])
                ]
                row["env_vars"] = {
                    f.get("name"): str(f.get("value"))
                    for f in settings.get("databaseFlags") or []
                }
                try:
                    users_resp = api.users().list(
                        project=project_id, instance=i["name"]
                    ).execute()
                    row["db_users"] = [
                        {
                            "name": u.get("name"),
                            "host": u.get("host"),
                            "type": u.get("type"),
                        }
                        for u in users_resp.get("items") or []
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "instance_count": len(items),
            "public_instances": public_instances,
            "instances_without_ssl_requirement": no_ssl,
        }
