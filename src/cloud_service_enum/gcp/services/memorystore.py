"""Memorystore for Redis instances."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class MemorystoreService(GcpService):
    service_name = "memorystore"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import redis_v1
        except ImportError:
            missing_sdk(result, "google-cloud-redis")
            return
        client = redis_v1.CloudRedisClient(credentials=credentials)
        instances = safe_list(
            client.list_instances(request={"parent": f"projects/{project_id}/locations/-"})
        )
        for i in instances:
            result.resources.append(
                {
                    "kind": "redis-instance",
                    "id": i.name,
                    "name": i.name.split("/")[-1],
                    "project": project_id,
                    "location": i.location_id,
                    "tier": i.tier.name,
                    "memory_size_gb": i.memory_size_gb,
                    "redis_version": i.redis_version,
                    "auth_enabled": i.auth_enabled,
                    "transit_encryption_mode": i.transit_encryption_mode.name,
                    "state": i.state.name,
                }
            )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "instance_count": len(instances),
            "instances_without_transit_encryption": sum(
                1 for i in instances if i.transit_encryption_mode.name == "DISABLED"
            ),
        }
