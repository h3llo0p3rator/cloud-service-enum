"""Vertex AI model endpoints."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class VertexAiService(GcpService):
    service_name = "vertexai"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import aiplatform_v1
        except ImportError:
            missing_sdk(result, "google-cloud-aiplatform")
            return
        locations = ("us-central1", "us-east1", "europe-west4", "asia-northeast1")
        total_endpoints = 0
        total_models = 0
        for location in locations:
            endpoints_client = aiplatform_v1.EndpointServiceClient(
                credentials=credentials,
                client_options={"api_endpoint": f"{location}-aiplatform.googleapis.com"},
            )
            models_client = aiplatform_v1.ModelServiceClient(
                credentials=credentials,
                client_options={"api_endpoint": f"{location}-aiplatform.googleapis.com"},
            )
            parent = f"projects/{project_id}/locations/{location}"
            endpoints = safe_list(endpoints_client.list_endpoints(parent=parent))
            models = safe_list(models_client.list_models(parent=parent))
            total_endpoints += len(endpoints)
            total_models += len(models)
            for e in endpoints:
                result.resources.append(
                    {
                        "kind": "endpoint",
                        "id": e.name,
                        "name": e.display_name,
                        "project": project_id,
                        "location": location,
                        "network": e.network,
                        "enable_private_service_connect": e.enable_private_service_connect,
                        "deployed_models": len(e.deployed_models),
                    }
                )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "endpoint_count": total_endpoints,
            "model_count": total_models,
        }
