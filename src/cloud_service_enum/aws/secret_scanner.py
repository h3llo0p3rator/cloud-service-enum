"""S3-specific wrappers around :mod:`cloud_service_enum.core.secrets`.

Provides the bucket-object listing + fetching glue; the actual regex
detection is shared with every other provider via the core module.
"""

from __future__ import annotations

import asyncio
from typing import Any

from cloud_service_enum.core.secrets import (
    TEXT_EXTENSIONS,
    ScanSummary,
    SecretFinding,
    ext,
    mask,
    scan_mapping,
    scan_text,
)

__all__ = [
    "TEXT_EXTENSIONS",
    "ScanSummary",
    "SecretFinding",
    "scan_bucket_for_secrets",
    "scan_mapping",
    "scan_text",
    "mask",
]


async def scan_bucket_for_secrets(
    s3: Any,
    bucket: str,
    *,
    file_limit: int = 100,
    size_limit_kb: int = 500,
) -> ScanSummary:
    """List up to ``file_limit`` objects in ``bucket`` and scan text files."""
    summary = ScanSummary()
    size_limit = size_limit_kb * 1024
    try:
        resp = await s3.list_objects_v2(Bucket=bucket, MaxKeys=file_limit)
    except Exception:  # noqa: BLE001
        return summary
    contents = resp.get("Contents") or []
    summary.files_found = len(contents)

    sem = asyncio.Semaphore(8)

    async def _scan(obj: dict[str, Any]) -> None:
        key = obj["Key"]
        size = obj.get("Size") or 0
        if ext(key) not in TEXT_EXTENSIONS:
            summary.files_skipped_type += 1
            return
        if size > size_limit:
            summary.files_skipped_size += 1
            return
        async with sem:
            body = await _read(s3, bucket, key)
        if body is None:
            return
        summary.files_scanned += 1
        summary.findings.extend(scan_text(key, body))

    await asyncio.gather(*(_scan(o) for o in contents), return_exceptions=True)
    return summary


async def _read(s3: Any, bucket: str, key: str) -> str | None:
    try:
        resp = await s3.get_object(Bucket=bucket, Key=key)
        body = await resp["Body"].read()
    except Exception:  # noqa: BLE001
        return None
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None
