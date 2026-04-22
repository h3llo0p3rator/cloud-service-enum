"""Cloud KMS key rings and keys."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class KmsService(GcpService):
    service_name = "kms"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import kms
        except ImportError:
            missing_sdk(result, "google-cloud-kms")
            return
        client = kms.KeyManagementServiceClient(credentials=credentials)
        locations_client = client.transport._host  # unused; enumerate locations per-key-ring via list
        rings = []
        try:
            for loc in ("global", "us", "europe", "asia"):
                parent = f"projects/{project_id}/locations/{loc}"
                rings.extend(safe_list(client.list_key_rings(parent=parent)))
        except Exception:  # noqa: BLE001
            pass
        keys: list[Any] = []
        for ring in rings:
            keys.extend(safe_list(client.list_crypto_keys(parent=ring.name)))
        focused = self.is_focused_on()
        rotation_enabled = 0
        for k in keys:
            if k.rotation_period and k.rotation_period.seconds:
                rotation_enabled += 1
            row = {
                "kind": "crypto-key",
                "id": k.name,
                "name": k.name.split("/")[-1],
                "project": project_id,
                "ring": k.name.split("/")[-3],
                "location": k.name.split("/")[-5],
                "purpose": k.purpose.name,
                "rotation_period_s": k.rotation_period.seconds if k.rotation_period else None,
                "next_rotation": k.next_rotation_time.isoformat() if k.next_rotation_time else None,
                "destroy_scheduled_duration": str(k.destroy_scheduled_duration) if k.destroy_scheduled_duration else None,
            }
            if focused:
                try:
                    iam = client.get_iam_policy(request={"resource": k.name})
                    row["role_bindings"] = [
                        {"role": b.role, "members": list(b.members)}
                        for b in iam.bindings
                    ]
                except Exception:  # noqa: BLE001
                    pass
                try:
                    versions = safe_list(client.list_crypto_key_versions(parent=k.name))
                    row["key_versions"] = [
                        {
                            "name": v.name.split("/")[-1],
                            "state": v.state.name,
                            "create_time": v.create_time.isoformat() if v.create_time else None,
                            "import_time": v.import_time.isoformat() if v.import_time else None,
                            "algorithm": v.algorithm.name,
                        }
                        for v in versions
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "keyring_count": len(rings),
            "key_count": len(keys),
            "keys_with_rotation": rotation_enabled,
        }
