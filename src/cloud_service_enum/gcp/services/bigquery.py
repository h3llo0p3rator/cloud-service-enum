"""BigQuery datasets and tables."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk


class BigQueryService(GcpService):
    service_name = "bigquery"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import bigquery
        except ImportError:
            missing_sdk(result, "google-cloud-bigquery")
            return
        client = bigquery.Client(project=project_id, credentials=credentials)
        datasets = list(client.list_datasets(project=project_id))
        cmek_datasets = 0
        focused = self.is_focused_on()
        for d in datasets:
            ds = client.get_dataset(d.reference)
            cmek = ds.default_encryption_configuration
            if cmek:
                cmek_datasets += 1
            row = {
                "kind": "dataset",
                "id": ds.full_dataset_id,
                "name": ds.dataset_id,
                "project": project_id,
                "location": ds.location,
                "default_table_expiration_ms": ds.default_table_expiration_ms,
                "cmek_key": cmek.kms_key_name if cmek else None,
                "labels": dict(ds.labels) if ds.labels else {},
            }
            if focused:
                row["role_bindings"] = [
                    {
                        "role": entry.role,
                        "members": [
                            f"{entry.entity_type}:{entry.entity_id}"
                        ],
                    }
                    for entry in ds.access_entries or []
                    if entry.role
                ]
                try:
                    tables = list(client.list_tables(ds.reference, max_results=50))
                    row["tables"] = [
                        {
                            "name": t.table_id,
                            "type": t.table_type,
                        }
                        for t in tables
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "dataset_count": len(datasets),
            "cmek_datasets": cmek_datasets,
        }
