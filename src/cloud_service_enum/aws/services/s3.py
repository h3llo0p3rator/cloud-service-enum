"""S3 enumeration with CIS v6 field enrichment."""

from __future__ import annotations

import asyncio
from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.aws.secret_scanner import scan_bucket_for_secrets
from cloud_service_enum.core.loot import loot_destination
from cloud_service_enum.core.models import ServiceResult


class S3Service(AwsService):
    service_name = "s3"
    is_regional = False

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("s3") as s3:
            buckets = (await s3.list_buckets()).get("Buckets", []) or []
            records = await asyncio.gather(
                *(self._bucket_details(s3, b, ctx) for b in buckets),
                return_exceptions=True,
            )

        public = 0
        unencrypted = 0
        total_secrets = 0
        for rec in records:
            if isinstance(rec, Exception):
                result.errors.append(str(rec))
                continue
            result.resources.append(rec)
            if rec.get("public_access"):
                public += 1
            if not rec.get("encryption"):
                unencrypted += 1
            total_secrets += len(rec.get("secrets_found") or [])
        if ctx.scope.download:
            downloaded = await self._download_objects(s3, buckets, ctx)
            result.resources.extend(downloaded)

        result.cis_fields = {
            "bucket_count": len(buckets),
            "public_buckets": public,
            "unencrypted_buckets": unencrypted,
        }
        if ctx.scope.s3_secret_scan:
            result.cis_fields["secrets_found"] = total_secrets
        if ctx.scope.download:
            result.cis_fields["objects_downloaded"] = sum(
                1 for r in result.resources if r.get("kind") == "downloaded_object"
            )

    async def _bucket_details(
        self, s3: Any, bucket: dict[str, Any], ctx: ServiceContext
    ) -> dict[str, Any]:
        name = bucket["Name"]
        loc = await safe(s3.get_bucket_location(Bucket=name))
        enc = await safe(s3.get_bucket_encryption(Bucket=name))
        ver = await safe(s3.get_bucket_versioning(Bucket=name))
        pab = await safe(s3.get_public_access_block(Bucket=name))
        logging = await safe(s3.get_bucket_logging(Bucket=name))
        pol = await safe(s3.get_bucket_policy_status(Bucket=name))
        lifecycle = await safe(s3.get_bucket_lifecycle_configuration(Bucket=name))
        ownership = await safe(s3.get_bucket_ownership_controls(Bucket=name))

        pab_cfg = (pab or {}).get("PublicAccessBlockConfiguration", {})
        record: dict[str, Any] = {
            "kind": "bucket",
            "id": name,
            "name": name,
            "region": (loc or {}).get("LocationConstraint") or "us-east-1",
            "created": bucket.get("CreationDate"),
            "encryption": bool(
                (enc or {}).get("ServerSideEncryptionConfiguration", {}).get("Rules")
            ),
            "versioning": (ver or {}).get("Status") == "Enabled",
            "mfa_delete": (ver or {}).get("MFADelete") == "Enabled",
            "public_access_block": pab_cfg,
            "public_access": not all(
                [
                    pab_cfg.get("BlockPublicAcls", False),
                    pab_cfg.get("IgnorePublicAcls", False),
                    pab_cfg.get("BlockPublicPolicy", False),
                    pab_cfg.get("RestrictPublicBuckets", False),
                ]
            ),
            "logging_enabled": bool((logging or {}).get("LoggingEnabled")),
            "policy_is_public": (pol or {}).get("PolicyStatus", {}).get("IsPublic", False),
            "lifecycle_rules": len((lifecycle or {}).get("Rules", []) or []),
            "ownership": (
                (ownership or {})
                .get("OwnershipControls", {})
                .get("Rules", [{}])[0]
                .get("ObjectOwnership")
            ),
        }
        if ctx.scope.s3_secret_scan:
            summary = await scan_bucket_for_secrets(
                s3,
                name,
                file_limit=ctx.scope.s3_scan_file_limit,
                size_limit_kb=ctx.scope.s3_scan_size_limit_kb,
            )
            record["scan_files_found"] = summary.files_found
            record["scan_files_scanned"] = summary.files_scanned
            record["scan_files_skipped_size"] = summary.files_skipped_size
            record["scan_files_skipped_type"] = summary.files_skipped_type
            record["secrets_found"] = [f.as_dict() for f in summary.findings]
        return record

    async def _download_objects(
        self,
        s3: Any,
        buckets: list[dict[str, Any]],
        ctx: ServiceContext,
    ) -> list[dict[str, Any]]:
        selected_buckets = set(ctx.scope.download_buckets or [])
        selected_files = set(ctx.scope.download_files or [])
        rows: list[dict[str, Any]] = []
        for bucket in buckets:
            name = bucket.get("Name")
            if not name:
                continue
            if selected_buckets and name not in selected_buckets:
                continue
            try:
                paginator = s3.get_paginator("list_objects_v2")
                async for page in paginator.paginate(Bucket=name):
                    for obj in page.get("Contents", []) or []:
                        key = obj.get("Key")
                        if not key:
                            continue
                        if not ctx.scope.download_all and selected_files and key not in selected_files:
                            continue
                        if not ctx.scope.download_all and not selected_files:
                            continue
                        payload = await safe(s3.get_object(Bucket=name, Key=key))
                        if not payload:
                            continue
                        body = payload.get("Body")
                        if body is None:
                            continue
                        blob = await body.read()
                        destination = loot_destination(owner=name, key=key)
                        destination.write_bytes(blob)
                        rows.append(
                            {
                                "kind": "downloaded_object",
                                "id": f"{name}/{key}",
                                "name": key,
                                "bucket": name,
                                "bytes": len(blob),
                                "loot_path": str(destination),
                            }
                        )
            except Exception:  # noqa: BLE001
                continue
        return rows
