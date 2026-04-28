"""GCS buckets."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.loot import loot_destination
from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk


class StorageService(GcpService):
    service_name = "storage"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import storage as gcs
        except ImportError:
            missing_sdk(result, "google-cloud-storage")
            return
        from cloud_service_enum.core.secrets import (
            TEXT_EXTENSIONS,
            ScanSummary,
            scan_text,
        )

        focused = self.is_focused_on()
        secret_scan = bool(self.scope and self.scope.secret_scan)
        scope = self.scope
        file_limit = scope.s3_scan_file_limit if scope else 100
        size_limit_kb = scope.s3_scan_size_limit_kb if scope else 500

        client = gcs.Client(project=project_id, credentials=credentials)
        buckets = list(client.list_buckets())
        uniform_access = 0
        retention_enabled = 0
        public = 0
        global_summary = ScanSummary(findings=[])
        downloaded_count = 0
        for b in buckets:
            b.reload()
            ubl = bool(b.iam_configuration.uniform_bucket_level_access_enabled)
            if ubl:
                uniform_access += 1
            if b.retention_period:
                retention_enabled += 1
            bindings: list[dict[str, Any]] = []
            try:
                iam = b.get_iam_policy(requested_policy_version=3)
                bindings = [
                    {"role": bin_.get("role"), "members": list(bin_.get("members", []))}
                    for bin_ in iam.bindings
                ]
                is_public = any(
                    m in {"allUsers", "allAuthenticatedUsers"}
                    for bin_ in bindings
                    for m in bin_["members"]
                )
            except Exception:  # noqa: BLE001
                is_public = False
            if is_public:
                public += 1
            row = {
                "kind": "bucket",
                "id": b.name,
                "name": b.name,
                "project": project_id,
                "location": b.location,
                "storage_class": b.storage_class,
                "versioning": b.versioning_enabled,
                "uniform_bucket_level_access": ubl,
                "encryption_default_kms": b.default_kms_key_name,
                "retention_period_s": b.retention_period,
                "public_access_prevention": b.iam_configuration.public_access_prevention,
                "is_public": is_public,
                "logging": bool(b.get_logging()),
            }
            if focused:
                if bindings:
                    row["role_bindings"] = bindings
                if secret_scan:
                    bucket_summary = _scan_bucket_for_secrets(
                        b, file_limit, size_limit_kb, scan_text, TEXT_EXTENSIONS
                    )
                    if bucket_summary.findings:
                        row["secrets_found"] = [
                            {**f.as_dict(), "file": f"gs://{b.name}/{f.file}"}
                            for f in bucket_summary.findings
                        ]
                    row["scan_files_found"] = bucket_summary.files_found
                    row["scan_files_scanned"] = bucket_summary.files_scanned
                    row["scan_bytes_scanned"] = bucket_summary.bytes_scanned
                    global_summary.files_found += bucket_summary.files_found
                    global_summary.files_scanned += bucket_summary.files_scanned
                    global_summary.bytes_scanned += bucket_summary.bytes_scanned
                    global_summary.findings.extend(bucket_summary.findings)
            result.resources.append(row)
            if scope and scope.download:
                downloaded = _download_bucket_objects(
                    b,
                    scope.download_buckets,
                    scope.download_files,
                    scope.download_all,
                )
                downloaded_count += len(downloaded)
                result.resources.extend(downloaded)
        if focused and secret_scan:
            result.cis_fields["secret_scan"] = {
                "files_found": global_summary.files_found,
                "files_scanned": global_summary.files_scanned,
                "bytes_scanned": global_summary.bytes_scanned,
                "findings": len(global_summary.findings),
            }
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "bucket_count": len(buckets),
            "buckets_with_uniform_access": uniform_access,
            "buckets_with_retention": retention_enabled,
            "public_buckets": public,
        }
        if scope and scope.download:
            result.cis_fields.setdefault("per_project", {})[project_id]["objects_downloaded"] = downloaded_count


def _scan_bucket_for_secrets(
    bucket: Any,
    file_limit: int,
    size_limit_kb: int,
    scan_text_fn: Any,
    text_extensions: Any,
) -> Any:
    from cloud_service_enum.core.secrets import ScanSummary

    summary = ScanSummary(findings=[])
    size_limit_bytes = size_limit_kb * 1024
    for blob in bucket.list_blobs(max_results=max(file_limit * 4, file_limit + 50)):
        if summary.files_scanned >= file_limit:
            break
        ext = "." + blob.name.rsplit(".", 1)[-1].lower() if "." in blob.name else ""
        if ext not in text_extensions:
            continue
        summary.files_found += 1
        if blob.size and blob.size > size_limit_bytes:
            continue
        try:
            data = blob.download_as_bytes(end=size_limit_bytes - 1)
            text = data.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        summary.files_scanned += 1
        summary.bytes_scanned += len(data)
        summary.findings.extend(scan_text_fn(blob.name, text))
    return summary


def _download_bucket_objects(
    bucket: Any,
    selected_buckets: list[str],
    selected_files: list[str],
    download_all: bool,
) -> list[dict[str, Any]]:
    if selected_buckets and bucket.name not in set(selected_buckets):
        return []
    file_filter = set(selected_files or [])
    rows: list[dict[str, Any]] = []
    try:
        for blob in bucket.list_blobs():
            name = blob.name
            if not download_all and file_filter and name not in file_filter:
                continue
            if not download_all and not file_filter:
                continue
            destination = loot_destination(owner=bucket.name, key=name)
            blob.download_to_filename(str(destination))
            rows.append(
                {
                    "kind": "downloaded_object",
                    "id": f"{bucket.name}/{name}",
                    "name": name,
                    "bucket": bucket.name,
                    "bytes": blob.size,
                    "loot_path": str(destination),
                }
            )
    except Exception:  # noqa: BLE001
        return rows
    return rows
