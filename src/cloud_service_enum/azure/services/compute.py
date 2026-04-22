"""VMs, disks and snapshots."""

from __future__ import annotations

from azure.mgmt.compute.aio import ComputeManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class ComputeService(AzureService):
    service_name = "compute"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        import base64

        from cloud_service_enum.core.secrets import scan_text

        focused = self.is_focused_on()
        secret_scan = bool(self.scope and self.scope.secret_scan)
        async with ComputeManagementClient(auth.credential(), subscription_id) as client:
            vms = await iter_async(client.virtual_machines.list_all())
            disks = await iter_async(client.disks.list())
            snapshots = await iter_async(client.snapshots.list())
            for v in vms:
                os_disk = v.storage_profile.os_disk if v.storage_profile else None
                row = {
                    "kind": "vm",
                    "id": v.id,
                    "name": v.name,
                    "location": v.location,
                    "subscription": subscription_id,
                    "vm_size": v.hardware_profile.vm_size if v.hardware_profile else None,
                    "os": (v.storage_profile.os_disk.os_type if v.storage_profile and v.storage_profile.os_disk else None),
                    "admin_username": v.os_profile.admin_username if v.os_profile else None,
                    "encryption_at_host": v.security_profile.encryption_at_host if v.security_profile else None,
                    "secure_boot": (v.security_profile.uefi_settings.secure_boot_enabled if v.security_profile and v.security_profile.uefi_settings else None),
                    "vtpm": (v.security_profile.uefi_settings.v_tpm_enabled if v.security_profile and v.security_profile.uefi_settings else None),
                    "os_disk_encryption": os_disk.managed_disk.id if os_disk and os_disk.managed_disk else None,
                }
                attach_identity(row, v)
                if focused:
                    rg = v.id.split("/")[4]
                    custom = (
                        v.os_profile
                        and v.os_profile.custom_data
                        or None
                    )
                    if custom:
                        try:
                            decoded = base64.b64decode(custom).decode(
                                "utf-8", errors="replace"
                            )
                            row["startup_script"] = decoded
                            row["script_language"] = "bash"
                            if secret_scan:
                                hits = scan_text(f"{v.name}.custom_data", decoded)
                                if hits:
                                    row["secrets_found"] = [h.as_dict() for h in hits]
                        except Exception:  # noqa: BLE001
                            pass
                    try:
                        exts = await client.virtual_machine_extensions.list(rg, v.name)
                        row["extensions"] = [
                            {
                                "name": e.name,
                                "publisher": e.publisher,
                                "type": e.type_properties_type,
                                "version": e.type_handler_version,
                                "settings": e.settings,
                            }
                            for e in (getattr(exts, "value", None) or [])
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                result.resources.append(row)
        for d in disks:
            result.resources.append(
                {
                    "kind": "disk",
                    "id": d.id,
                    "name": d.name,
                    "location": d.location,
                    "subscription": subscription_id,
                    "size_gb": d.disk_size_gb,
                    "encryption_type": d.encryption.type if d.encryption else None,
                    "disk_encryption_set": d.encryption.disk_encryption_set_id if d.encryption else None,
                    "public_network_access": d.public_network_access,
                }
            )
        for s in snapshots:
            result.resources.append(
                {
                    "kind": "snapshot",
                    "id": s.id,
                    "name": s.name,
                    "location": s.location,
                    "subscription": subscription_id,
                    "public_network_access": s.public_network_access,
                    "encryption_type": s.encryption.type if s.encryption else None,
                }
            )
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "vm_count": len(vms),
            "disk_count": len(disks),
            "snapshots": len(snapshots),
            "vms_without_encryption_at_host": sum(
                1 for v in vms if not (v.security_profile and v.security_profile.encryption_at_host)
            ),
        }
