"""Legacy Google Container Registry (gcr.io) images and tags.

GCR is distinct from Artifact Registry. Images live under hosts such as
``us.gcr.io/<project>/...`` and are exposed through the Docker Registry
HTTP API v2 (the same surface ``gcloud container images list`` uses).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, format_gcp_error

_GCR_HOSTS = ("gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io")
_MAX_REPOS = 500
_TIMEOUT = 30.0


class GcrService(GcpService):
    service_name = "gcr"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        try:
            token = _access_token(credentials)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"[{project_id}] gcr token: {format_gcp_error(exc)}")
            return

        image_count = 0
        with httpx.Client(timeout=_TIMEOUT, auth=("_token", token)) as client:
            for host in _GCR_HOSTS:
                try:
                    entries = _discover(client, host, project_id)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(
                        f"[{project_id}] {host}: {format_gcp_error(exc)}"
                    )
                    continue
                if not entries:
                    continue
                for path, payload in entries:
                    uri = f"{host}/{path}"
                    tags = list(payload.get("tags") or [])
                    # tags/list is already fetched during discovery — always surface tags.
                    row: dict[str, Any] = {
                        "kind": "gcr-image",
                        "id": uri,
                        "name": path,
                        "project": project_id,
                        "host": host,
                        "uri": uri,
                        "tags": tags,
                        "tag_count": len(tags),
                    }
                    if focused:
                        images = _images_from_manifest(payload.get("manifest") or {})
                        row["image_count"] = len(images)
                        row["images"] = images
                    result.resources.append(row)
                    image_count += 1

        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "gcr_image_count": image_count,
        }


def _access_token(credentials: Any) -> str:
    token = getattr(credentials, "token", None)
    if token and not getattr(credentials, "expired", False):
        return token
    from google.auth.transport.requests import Request

    try:
        credentials.refresh(Request())
    except Exception:
        if token:
            return token
        raise
    if not credentials.token:
        raise RuntimeError("GCP credentials have no access token")
    return credentials.token


def _tags_list(client: httpx.Client, host: str, path: str) -> dict[str, Any] | None:
    url = f"https://{host}/v2/{quote(path, safe='/')}/tags/list"
    resp = client.get(url)
    if resp.status_code in {401, 403, 404}:
        return None
    if resp.status_code != 200:
        resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, dict) else None


def _discover(
    client: httpx.Client, host: str, project_id: str
) -> list[tuple[str, dict[str, Any]]]:
    """Walk ``/v2/<path>/tags/list`` from the project root, following ``child``.

    Falls back to ``/_catalog`` filtered by project prefix when the project
    root walk yields nothing (some hosts only answer catalog).
    """
    found: list[tuple[str, dict[str, Any]]] = []
    queue = [project_id]
    seen: set[str] = set()
    while queue and len(found) < _MAX_REPOS:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        data = _tags_list(client, host, path)
        if data is None:
            continue
        if path != project_id:
            found.append((path, data))
        for child in data.get("child") or []:
            if isinstance(child, str) and child:
                queue.append(f"{path}/{child}")

    if found:
        return found

    # Catalog fallback — list repos under this project only.
    for name in _catalog(client, host, project_id):
        if len(found) >= _MAX_REPOS:
            break
        data = _tags_list(client, host, name) or {}
        found.append((name, data))
    return found


def _catalog(client: httpx.Client, host: str, project_id: str) -> list[str]:
    names: list[str] = []
    last: str | None = None
    prefix = f"{project_id}/"
    while len(names) < _MAX_REPOS:
        params: dict[str, str] = {"n": "1000"}
        if last:
            params["last"] = last
        resp = client.get(f"https://{host}/v2/_catalog", params=params)
        if resp.status_code in {401, 403, 404}:
            break
        if resp.status_code != 200:
            resp.raise_for_status()
        batch = list((resp.json() or {}).get("repositories") or [])
        if not batch:
            break
        for name in batch:
            if name == project_id or name.startswith(prefix):
                if name != project_id:
                    names.append(name)
        last = batch[-1]
        if len(batch) < 1000:
            break
    return names


def _images_from_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    images: list[dict[str, Any]] = []
    for digest, meta in manifest.items():
        if not isinstance(meta, dict):
            continue
        uploaded = meta.get("timeUploadedMs") or meta.get("timeCreatedMs")
        upload_time = None
        if uploaded is not None:
            try:
                upload_time = datetime.fromtimestamp(
                    int(uploaded) / 1000.0, tz=timezone.utc
                ).isoformat()
            except (TypeError, ValueError, OSError):
                upload_time = str(uploaded)
        size = meta.get("imageSizeBytes")
        try:
            size_bytes = int(size) if size is not None else None
        except (TypeError, ValueError):
            size_bytes = None
        images.append(
            {
                "digest": digest,
                "tags": list(meta.get("tag") or []),
                "size_bytes": size_bytes,
                "upload_time": upload_time,
            }
        )
    return images
