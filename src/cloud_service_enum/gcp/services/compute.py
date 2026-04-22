"""Compute Engine instances, disks and images."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class ComputeService(GcpService):
    service_name = "compute"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import compute_v1
        except ImportError:
            missing_sdk(result, "google-cloud-compute")
            return
        from cloud_service_enum.core.secrets import scan_text

        focused = self.is_focused_on()
        secret_scan = bool(self.scope and self.scope.secret_scan)
        instances_client = compute_v1.InstancesClient(credentials=credentials)
        pages = instances_client.aggregated_list(project=project_id)
        instance_count = 0
        instances_with_default_sa = 0
        instances_with_public_ip = 0
        for zone, scoped in pages:
            for inst in scoped.instances or []:
                instance_count += 1
                nic = (inst.network_interfaces or [None])[0]
                has_public = bool(nic and nic.access_configs)
                sa = (inst.service_accounts or [None])[0]
                is_default_sa = bool(sa and sa.email and sa.email.endswith("-compute@developer.gserviceaccount.com"))
                if has_public:
                    instances_with_public_ip += 1
                if is_default_sa:
                    instances_with_default_sa += 1
                row = {
                    "kind": "instance",
                    "id": str(inst.id),
                    "name": inst.name,
                    "project": project_id,
                    "zone": zone.split("/")[-1],
                    "machine_type": inst.machine_type.split("/")[-1],
                    "status": inst.status,
                    "network": nic.network.split("/")[-1] if nic else None,
                    "internal_ip": nic.network_i_p if nic else None,
                    "has_public_ip": has_public,
                    "service_account": sa.email if sa else None,
                    "scopes": list(sa.scopes) if sa else None,
                    "can_ip_forward": inst.can_ip_forward,
                    "shielded_vm": inst.shielded_instance_config.enable_secure_boot if inst.shielded_instance_config else None,
                    "deletion_protection": inst.deletion_protection,
                    "labels": dict(inst.labels) if inst.labels else {},
                }
                if focused and inst.metadata:
                    items = {
                        item.key: item.value or ""
                        for item in inst.metadata.items or []
                    }
                    startup = items.get("startup-script") or items.get(
                        "windows-startup-script-ps1"
                    )
                    if startup:
                        row["startup_script"] = startup
                        row["script_language"] = (
                            "powershell"
                            if "windows-startup" in items
                            else "bash"
                        )
                        if secret_scan:
                            hits = scan_text(f"{inst.name}.startup-script", startup)
                            if hits:
                                row["secrets_found"] = [h.as_dict() for h in hits]
                    if items:
                        row["env_vars"] = {
                            k: v for k, v in items.items() if k != "startup-script"
                        }
                result.resources.append(row)
        disks_client = compute_v1.DisksClient(credentials=credentials)
        disk_pages = disks_client.aggregated_list(project=project_id)
        for _zone, scoped in disk_pages:
            for d in scoped.disks or []:
                result.resources.append(
                    {
                        "kind": "disk",
                        "id": str(d.id),
                        "name": d.name,
                        "project": project_id,
                        "zone": d.zone.split("/")[-1] if d.zone else None,
                        "size_gb": d.size_gb,
                        "encryption_key_type": (
                            "CMEK" if d.disk_encryption_key and d.disk_encryption_key.kms_key_name else "Google"
                        ),
                    }
                )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "instance_count": instance_count,
            "instances_with_default_sa": instances_with_default_sa,
            "instances_with_public_ip": instances_with_public_ip,
        }
