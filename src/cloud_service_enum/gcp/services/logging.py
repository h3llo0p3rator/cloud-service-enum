"""Cloud Logging sinks, log buckets and log-based metrics."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class LoggingService(GcpService):
    service_name = "logging"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud.logging_v2.services.config_service_v2 import (
                ConfigServiceV2Client,
            )
            from google.cloud.logging_v2.services.metrics_service_v2 import (
                MetricsServiceV2Client,
            )
        except ImportError:
            missing_sdk(result, "google-cloud-logging")
            return
        config = ConfigServiceV2Client(credentials=credentials)
        metrics = MetricsServiceV2Client(credentials=credentials)
        parent = f"projects/{project_id}"
        sinks = safe_list(config.list_sinks(parent=parent))
        buckets = safe_list(config.list_buckets(parent=f"{parent}/locations/global"))
        exclusions = safe_list(config.list_exclusions(parent=parent))
        metrics_list = safe_list(metrics.list_log_metrics(parent=parent))

        for s in sinks:
            result.resources.append(
                {
                    "kind": "sink",
                    "id": s.name,
                    "project": project_id,
                    "destination": s.destination,
                    "filter": s.filter,
                    "writer_identity": s.writer_identity,
                    "include_children": s.include_children,
                }
            )
        for b in buckets:
            result.resources.append(
                {
                    "kind": "log-bucket",
                    "id": b.name,
                    "project": project_id,
                    "retention_days": b.retention_days,
                    "locked": b.locked,
                    "lifecycle_state": b.lifecycle_state.name,
                    "cmek": bool(b.cmek_settings and b.cmek_settings.kms_key_name),
                }
            )
        for m in metrics_list:
            result.resources.append(
                {
                    "kind": "log-metric",
                    "id": m.name,
                    "project": project_id,
                    "filter": m.filter,
                }
            )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "sink_count": len(sinks),
            "log_bucket_count": len(buckets),
            "log_metric_count": len(metrics_list),
            "exclusion_count": len(exclusions),
            "locked_buckets": sum(1 for b in buckets if b.locked),
        }
