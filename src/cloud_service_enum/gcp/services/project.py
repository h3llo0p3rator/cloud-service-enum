"""Project metadata and IAM policy summary."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk


class ProjectService(GcpService):
    service_name = "project"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import resourcemanager_v3
        except ImportError:
            missing_sdk(result, "google-cloud-resource-manager")
            return
        focused = self.is_focused_on()
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        project = client.get_project(name=f"projects/{project_id}")
        iam = client.get_iam_policy(resource=f"projects/{project_id}")
        bindings = [{"role": b.role, "members": list(b.members)} for b in iam.bindings]
        proj_row = {
            "kind": "project",
            "id": project_id,
            "name": project.display_name,
            "parent": project.parent,
            "state": project.state.name,
            "create_time": project.create_time.isoformat() if project.create_time else None,
            "labels": dict(project.labels),
            "iam_binding_count": len(bindings),
        }
        if focused:
            proj_row["role_bindings"] = bindings
        result.resources.append(proj_row)
        if not focused:
            for b in bindings:
                result.resources.append({"kind": "iam-binding", "id": f"{project_id}:{b['role']}", **b})
        user_primitive = sum(
            len(b["members"])
            for b in bindings
            if b["role"] in {"roles/owner", "roles/editor", "roles/viewer"}
            for m in b["members"]
            if m.startswith("user:")
        )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "binding_count": len(bindings),
            "user_members_with_primitive_roles": user_primitive,
        }
