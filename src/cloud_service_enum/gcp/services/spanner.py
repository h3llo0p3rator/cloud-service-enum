"""Cloud Spanner instances and databases."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class SpannerService(GcpService):
    service_name = "spanner"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import (
                spanner_admin_database_v1,
                spanner_admin_instance_v1,
            )
        except ImportError:
            missing_sdk(result, "google-cloud-spanner")
            return
        instance_client = spanner_admin_instance_v1.InstanceAdminClient(credentials=credentials)
        db_client = spanner_admin_database_v1.DatabaseAdminClient(credentials=credentials)
        instances = safe_list(
            instance_client.list_instances(request={"parent": f"projects/{project_id}"})
        )
        focused = self.is_focused_on()
        dbs: list[Any] = []
        for i in instances:
            irow = {
                "kind": "instance",
                "id": i.name,
                "name": i.display_name,
                "project": project_id,
                "config": i.config,
                "state": i.state.name,
                "node_count": i.node_count,
                "processing_units": i.processing_units,
            }
            if focused:
                try:
                    iam = instance_client.get_iam_policy(request={"resource": i.name})
                    irow["role_bindings"] = [
                        {"role": b.role, "members": list(b.members)}
                        for b in iam.bindings
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(irow)
            instance_dbs = safe_list(db_client.list_databases(request={"parent": i.name}))
            dbs.extend(instance_dbs)
            for d in instance_dbs:
                result.resources.append(
                    {
                        "kind": "database",
                        "id": d.name,
                        "name": d.name.split("/")[-1],
                        "project": project_id,
                        "state": d.state.name,
                        "encryption_info": d.encryption_config.kms_key_name if d.encryption_config else None,
                        "version_retention_period": d.version_retention_period,
                    }
                )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "instance_count": len(instances),
            "database_count": len(dbs),
        }
