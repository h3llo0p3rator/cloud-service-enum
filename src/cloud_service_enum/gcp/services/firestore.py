"""Firestore databases."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk


class FirestoreService(GcpService):
    service_name = "firestore"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import firestore_admin_v1
        except ImportError:
            missing_sdk(result, "google-cloud-firestore")
            return
        client = firestore_admin_v1.FirestoreAdminClient(credentials=credentials)
        resp = client.list_databases(request={"parent": f"projects/{project_id}"})
        dbs = list(resp.databases)
        for d in dbs:
            result.resources.append(
                {
                    "kind": "database",
                    "id": d.name,
                    "name": d.name.split("/")[-1],
                    "project": project_id,
                    "location": d.location_id,
                    "type": d.type_.name,
                    "concurrency_mode": d.concurrency_mode.name,
                    "app_engine_integration_mode": d.app_engine_integration_mode.name,
                    "point_in_time_recovery": d.point_in_time_recovery_enablement.name,
                    "delete_protection": d.delete_protection_state.name,
                    "cmek_config": d.cmek_config.kms_key_name if d.cmek_config else None,
                }
            )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "database_count": len(dbs),
            "with_pitr": sum(
                1 for d in dbs if d.point_in_time_recovery_enablement.name == "POINT_IN_TIME_RECOVERY_ENABLED"
            ),
        }
