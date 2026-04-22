"""Secret Manager secrets."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class SecretManagerService(GcpService):
    service_name = "secretmanager"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import secretmanager
        except ImportError:
            missing_sdk(result, "google-cloud-secret-manager")
            return
        focused = self.is_focused_on()
        client = secretmanager.SecretManagerServiceClient(credentials=credentials)
        secrets = safe_list(client.list_secrets(request={"parent": f"projects/{project_id}"}))
        with_replication = 0
        for s in secrets:
            if s.replication:
                with_replication += 1
            row = {
                "kind": "secret",
                "id": s.name,
                "name": s.name.split("/")[-1],
                "project": project_id,
                "create_time": s.create_time.isoformat() if s.create_time else None,
                "expire_time": s.expire_time.isoformat() if s.expire_time else None,
                "labels": dict(s.labels) if s.labels else {},
                "rotation_next": s.rotation.next_rotation_time.isoformat()
                if s.rotation and s.rotation.next_rotation_time
                else None,
                "rotation_period": str(s.rotation.rotation_period)
                if s.rotation and s.rotation.rotation_period
                else None,
            }
            if focused:
                try:
                    versions = safe_list(
                        client.list_secret_versions(request={"parent": s.name})
                    )
                    row["versions"] = [
                        {
                            "name": v.name.split("/")[-1],
                            "state": v.state.name,
                            "create_time": v.create_time.isoformat() if v.create_time else None,
                        }
                        for v in versions
                    ]
                except Exception:  # noqa: BLE001
                    pass
                try:
                    iam = client.get_iam_policy(request={"resource": s.name})
                    row["role_bindings"] = [
                        {"role": b.role, "members": list(b.members)}
                        for b in iam.bindings
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "secret_count": len(secrets),
            "secrets_with_rotation": sum(
                1 for s in secrets if s.rotation and s.rotation.rotation_period
            ),
        }
