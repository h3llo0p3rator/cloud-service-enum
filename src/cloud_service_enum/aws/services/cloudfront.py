"""CloudFront distributions (global)."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class CloudFrontService(AwsService):
    service_name = "cloudfront"
    is_regional = False

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("cloudfront") as cf:
            pages = await paginate(cf, "list_distributions")
            dists: list[dict[str, Any]] = []
            for page in pages:
                dists.extend((page.get("DistributionList") or {}).get("Items") or [])
            for d in dists:
                viewer_cert = d.get("ViewerCertificate", {}) or {}
                row: dict[str, Any] = {
                    "kind": "distribution",
                    "id": d["Id"],
                    "arn": d.get("ARN"),
                    "name": d.get("DomainName"),
                    "status": d.get("Status"),
                    "aliases": (d.get("Aliases") or {}).get("Items", []),
                    "origin_count": (d.get("Origins") or {}).get("Quantity", 0),
                    "enabled": d.get("Enabled", False),
                    "price_class": d.get("PriceClass"),
                    "http_version": d.get("HttpVersion"),
                    "web_acl_id": d.get("WebACLId"),
                    "tls_min": viewer_cert.get("MinimumProtocolVersion"),
                    "viewer_protocol_policy": (
                        (d.get("DefaultCacheBehavior") or {}).get("ViewerProtocolPolicy")
                    ),
                }
                if focused:
                    cfg_resp = await safe(cf.get_distribution_config(Id=d["Id"]))
                    cfg = (cfg_resp or {}).get("DistributionConfig") or {}
                    if cfg:
                        row["origins"] = [
                            {
                                "id": o.get("Id"),
                                "domain": o.get("DomainName"),
                                "path": o.get("OriginPath"),
                                "oai": (o.get("S3OriginConfig") or {}).get(
                                    "OriginAccessIdentity"
                                ),
                                "custom": bool(o.get("CustomOriginConfig")),
                            }
                            for o in (cfg.get("Origins") or {}).get("Items", []) or []
                        ]
                        lambdas = (
                            (cfg.get("DefaultCacheBehavior") or {})
                            .get("LambdaFunctionAssociations")
                            or {}
                        )
                        row["lambda_at_edge"] = [
                            la.get("LambdaFunctionARN")
                            for la in lambdas.get("Items") or []
                        ]
                result.resources.append(row)
        result.cis_fields = {
            "distribution_count": len(dists),
            "distributions_with_waf": sum(1 for d in dists if d.get("WebACLId")),
            "distributions_https_only": sum(
                1
                for d in dists
                if (d.get("DefaultCacheBehavior") or {}).get("ViewerProtocolPolicy")
                in {"https-only", "redirect-to-https"}
            ),
        }
