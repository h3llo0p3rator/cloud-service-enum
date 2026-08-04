"""App Engine applications, services, and versions."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, format_gcp_error, missing_sdk, safe_list

_MAX_INSTANCES = 50


class AppEngineService(GcpService):
    service_name = "appengine"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import appengine_admin_v1
            from google.api_core import exceptions as gax_exc
        except ImportError:
            missing_sdk(result, "google-cloud-appengine-admin")
            return

        from cloud_service_enum.core.secrets import scan_mapping

        focused = self.is_focused_on()
        secret_scan = bool(self.scope and self.scope.secret_scan)
        apps_client = appengine_admin_v1.ApplicationsClient(credentials=credentials)
        services_client = appengine_admin_v1.ServicesClient(credentials=credentials)
        versions_client = appengine_admin_v1.VersionsClient(credentials=credentials)
        app_name = f"apps/{project_id}"

        try:
            app = apps_client.get_application(name=app_name)
        except gax_exc.NotFound:
            result.cis_fields.setdefault("per_project", {})[project_id] = {
                "app_engine_enabled": False,
                "service_count": 0,
                "version_count": 0,
            }
            return
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"[{project_id}] application: {format_gcp_error(exc)}")
            return

        result.resources.append(
            {
                "kind": "application",
                "id": app.name,
                "name": project_id,
                "project": project_id,
                "location": app.location_id,
                "serving_status": app.serving_status.name if app.serving_status else None,
                "default_hostname": app.default_hostname or None,
                "service_account": app.service_account or None,
                "database_type": app.database_type.name if app.database_type else None,
                "gcr_domain": app.gcr_domain or None,
            }
        )

        services = safe_list(services_client.list_services(parent=app_name))
        version_count = 0
        serving_versions = 0

        view = (
            appengine_admin_v1.VersionView.FULL
            if focused
            else appengine_admin_v1.VersionView.BASIC
        )
        instances_client = (
            appengine_admin_v1.InstancesClient(credentials=credentials)
            if focused
            else None
        )

        for svc in services:
            svc_id = svc.name.split("/")[-1]
            traffic = (
                dict(svc.split.allocations)
                if svc.split and svc.split.allocations
                else {}
            )
            result.resources.append(
                {
                    "kind": "service",
                    "id": svc.name,
                    "name": svc_id,
                    "project": project_id,
                    "traffic_split": {
                        version_id: float(frac) for version_id, frac in traffic.items()
                    },
                }
            )

            try:
                versions = safe_list(
                    versions_client.list_versions(
                        request={"parent": svc.name, "view": view}
                    )
                )
            except Exception as exc:  # noqa: BLE001
                result.errors.append(
                    f"[{project_id}] {svc_id} versions: {format_gcp_error(exc)}"
                )
                continue

            for ver in versions:
                version_count += 1
                status = ver.serving_status.name if ver.serving_status else None
                if status == "SERVING":
                    serving_versions += 1
                ver_id = ver.name.split("/")[-1]
                row: dict[str, Any] = {
                    "kind": "version",
                    "id": ver.name,
                    "name": ver_id,
                    "service": svc_id,
                    "project": project_id,
                    "runtime": ver.runtime or None,
                    "env": ver.env or None,
                    "serving_status": status,
                    "service_account": ver.service_account or None,
                    "created": ver.create_time.isoformat() if ver.create_time else None,
                    "version_url": ver.version_url or None,
                    "instance_class": ver.instance_class or None,
                }
                if focused:
                    env_vars = dict(ver.env_variables) if ver.env_variables else {}
                    if env_vars:
                        row["env_vars"] = env_vars
                        if secret_scan:
                            hits = scan_mapping(ver.name, env_vars)
                            if hits:
                                row["secrets_found"] = [h.as_dict() for h in hits]
                    if ver.inbound_services:
                        row["inbound_services"] = [
                            s.name if hasattr(s, "name") else str(s)
                            for s in ver.inbound_services
                        ]
                    if ver.network:
                        row["network"] = {
                            "name": ver.network.name or None,
                            "subnetwork_name": ver.network.subnetwork_name or None,
                            "forwarded_ports": list(ver.network.forwarded_ports or []),
                            "instance_tag": ver.network.instance_tag or None,
                        }
                    if ver.handlers:
                        row["handlers"] = [
                            {
                                "url_regex": h.url_regex or None,
                                "security_level": h.security_level.name
                                if h.security_level
                                else None,
                                "login": h.login.name if h.login else None,
                                "auth_fail_action": h.auth_fail_action.name
                                if h.auth_fail_action
                                else None,
                                "script_path": (h.script.path if h.script else None),
                            }
                            for h in ver.handlers
                        ]
                    if instances_client is not None:
                        try:
                            insts = safe_list(
                                instances_client.list_instances(parent=ver.name)
                            )[:_MAX_INSTANCES]
                            row["instance_count"] = len(insts)
                            row["instances"] = [
                                {
                                    "id": i.name.split("/")[-1],
                                    "vm_name": i.vm_name or None,
                                    "vm_ip": i.vm_ip or None,
                                    "vm_liveness": i.vm_liveness.name
                                    if i.vm_liveness
                                    else None,
                                    "availability": i.availability.name
                                    if i.availability
                                    else None,
                                }
                                for i in insts
                            ]
                        except Exception as exc:  # noqa: BLE001
                            result.errors.append(
                                f"[{project_id}] {svc_id}/{ver_id} instances: "
                                f"{format_gcp_error(exc)}"
                            )
                result.resources.append(row)

        if focused:
            try:
                fw = appengine_admin_v1.FirewallClient(credentials=credentials)
                for rule in safe_list(fw.list_ingress_rules(parent=app_name)):
                    result.resources.append(
                        {
                            "kind": "firewall-rule",
                            "id": rule.name or f"priority-{rule.priority}",
                            "name": rule.name or str(rule.priority),
                            "project": project_id,
                            "priority": rule.priority,
                            "action": rule.action.name if rule.action else None,
                            "source_range": rule.source_range or None,
                            "description": rule.description or None,
                        }
                    )
            except Exception as exc:  # noqa: BLE001
                result.errors.append(
                    f"[{project_id}] firewall: {format_gcp_error(exc)}"
                )

        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "app_engine_enabled": True,
            "service_count": len(services),
            "version_count": version_count,
            "serving_versions": serving_versions,
            "location": app.location_id,
        }