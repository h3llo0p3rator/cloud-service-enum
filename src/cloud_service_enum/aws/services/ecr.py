"""ECR — repositories, image tags, policies, lifecycle + cross-account access.

Container repos are a standard supply-chain attack surface: the repo
policy controls who can push/pull, lifecycle policies determine how long
malicious tags hang around, and scan findings tell an auditor how stale
the inventory is. Shallow runs return repo metadata; focused/deep mode
pulls per-image tags + repo policy bodies so the existing policy-document
renderer highlights cross-account principals.
"""

from __future__ import annotations

import json
from typing import Any

from cloud_service_enum.aws.base import (
    AwsService,
    ServiceContext,
    collect_items,
    paginate,
    safe,
)
from cloud_service_enum.core.models import ServiceResult

_IMAGE_PAGE_CAP = 100


class EcrService(AwsService):
    service_name = "ecr"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("ecr") as ecr:
            repos = collect_items(
                await paginate(ecr, "describe_repositories"), "repositories"
            )
            for repo in repos:
                name = repo["repositoryName"]
                enc = repo.get("encryptionConfiguration") or {}
                tags = repo.get("imageTagMutability")
                scan_cfg = repo.get("imageScanningConfiguration") or {}
                row: dict[str, Any] = {
                    "kind": "ecr-repo",
                    "id": name,
                    "arn": repo.get("repositoryArn"),
                    "name": name,
                    "region": ctx.region,
                    "uri": repo.get("repositoryUri"),
                    "registry_id": repo.get("registryId"),
                    "scan_on_push": scan_cfg.get("scanOnPush", False),
                    "immutable_tags": tags == "IMMUTABLE",
                    "encryption_type": enc.get("encryptionType"),
                    "kms_key": enc.get("kmsKey"),
                    "created_at": repo.get("createdAt"),
                }
                if focused:
                    await _enrich(ecr, name, row)
                result.resources.append(row)

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "repo_count": len(repos),
            "scan_on_push_enabled": sum(
                1 for r in result.resources
                if r.get("kind") == "ecr-repo" and r.get("scan_on_push")
            ),
            "immutable_tag_enabled": sum(
                1 for r in result.resources
                if r.get("kind") == "ecr-repo" and r.get("immutable_tags")
            ),
        }


async def _enrich(ecr: Any, name: str, row: dict[str, Any]) -> None:
    policy_resp = await safe(ecr.get_repository_policy(repositoryName=name))
    body = (policy_resp or {}).get("policyText")
    if isinstance(body, str) and body:
        try:
            row["policy_document"] = json.loads(body)
        except ValueError:
            row["policy_document"] = {"_raw": body}

    lifecycle_resp = await safe(ecr.get_lifecycle_policy(repositoryName=name))
    lifecycle_text = (lifecycle_resp or {}).get("lifecyclePolicyText")
    if isinstance(lifecycle_text, str) and lifecycle_text:
        try:
            row["lifecycle_policy"] = json.loads(lifecycle_text)
        except ValueError:
            row["lifecycle_policy"] = {"_raw": lifecycle_text}

    images_resp = await safe(ecr.describe_images(repositoryName=name, maxResults=_IMAGE_PAGE_CAP))
    images = (images_resp or {}).get("imageDetails") or []
    if images:
        row["image_count"] = len(images)
        row["images"] = [_image_entry(img) for img in images]


def _image_entry(img: dict[str, Any]) -> dict[str, Any]:
    findings = img.get("imageScanFindingsSummary") or {}
    counts = findings.get("findingSeverityCounts") or {}
    return {
        "digest": img.get("imageDigest"),
        "tags": img.get("imageTags") or [],
        "size_bytes": img.get("imageSizeInBytes"),
        "pushed_at": img.get("imagePushedAt"),
        "scan_status": (img.get("imageScanStatus") or {}).get("status"),
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
    }
