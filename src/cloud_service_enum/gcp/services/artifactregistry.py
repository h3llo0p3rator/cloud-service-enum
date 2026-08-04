"""Artifact Registry repositories and Docker images/tags."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, format_gcp_error, missing_sdk, safe_list


class ArtifactRegistryService(GcpService):
    service_name = "artifactregistry"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import artifactregistry_v1
        except ImportError:
            missing_sdk(result, "google-cloud-artifact-registry")
            return

        focused = self.is_focused_on()
        client = artifactregistry_v1.ArtifactRegistryClient(credentials=credentials)
        parent = f"projects/{project_id}/locations/-"
        repos = safe_list(client.list_repositories(parent=parent))

        docker_repos = 0
        docker_images = 0

        for repo in repos:
            parts = repo.name.split("/")
            location = parts[3] if len(parts) >= 4 else None
            name = parts[-1]
            fmt = repo.format.name if repo.format else None
            is_docker = fmt == "DOCKER"
            if is_docker:
                docker_repos += 1

            row: dict[str, Any] = {
                "kind": "repository",
                "id": repo.name,
                "name": name,
                "project": project_id,
                "location": location,
                "format": fmt,
                "mode": repo.mode.name if repo.mode else None,
                "description": repo.description or None,
                "create_time": repo.create_time.isoformat() if repo.create_time else None,
                "size_bytes": int(repo.size_bytes) if repo.size_bytes else None,
            }
            if is_docker and location:
                row["uri"] = f"{location}-docker.pkg.dev/{project_id}/{name}"

            if focused:
                if is_docker:
                    try:
                        images = safe_list(client.list_docker_images(parent=repo.name))
                        entries = [_docker_image_entry(img) for img in images]
                        row["image_count"] = len(entries)
                        row["images"] = entries
                        docker_images += len(entries)
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(
                            f"[{project_id}] {name} docker_images: {format_gcp_error(exc)}"
                        )
                try:
                    iam = client.get_iam_policy(request={"resource": repo.name})
                    row["role_bindings"] = [
                        {"role": b.role, "members": list(b.members)}
                        for b in iam.bindings
                    ]
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(
                        f"[{project_id}] {name} iam: {format_gcp_error(exc)}"
                    )

            result.resources.append(row)

        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "repository_count": len(repos),
            "docker_repository_count": docker_repos,
            "docker_image_count": docker_images,
        }


def _docker_image_entry(img: Any) -> dict[str, Any]:
    name = getattr(img, "name", "") or ""
    digest = None
    if "@" in name:
        digest = name.rsplit("@", 1)[-1]
    elif getattr(img, "uri", None) and "@" in img.uri:
        digest = img.uri.rsplit("@", 1)[-1]
    return {
        "uri": img.uri or None,
        "tags": list(img.tags) if img.tags else [],
        "digest": digest,
        "size_bytes": int(img.image_size_bytes) if img.image_size_bytes else None,
        "upload_time": img.upload_time.isoformat() if img.upload_time else None,
        "media_type": img.media_type or None,
    }
