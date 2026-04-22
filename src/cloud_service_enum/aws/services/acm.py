"""ACM certificates."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class AcmService(AwsService):
    service_name = "acm"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("acm") as acm:
            summaries = collect_items(
                await paginate(acm, "list_certificates"), "CertificateSummaryList"
            )
            for s in summaries:
                arn = s["CertificateArn"]
                detail = await safe(acm.describe_certificate(CertificateArn=arn))
                c = (detail or {}).get("Certificate") or s
                row: dict = {
                    "kind": "certificate",
                    "id": c.get("CertificateArn"),
                    "arn": c.get("CertificateArn"),
                    "name": c.get("DomainName"),
                    "region": ctx.region,
                    "status": c.get("Status"),
                    "in_use_by": c.get("InUseBy", []),
                    "key_algorithm": c.get("KeyAlgorithm"),
                    "sig_algorithm": c.get("SignatureAlgorithm"),
                    "not_before": c.get("NotBefore"),
                    "not_after": c.get("NotAfter"),
                    "renewal_eligibility": c.get("RenewalEligibility"),
                    "type": c.get("Type"),
                }
                if focused:
                    chain = await safe(acm.get_certificate(CertificateArn=arn))
                    if chain:
                        cert = chain.get("Certificate") or ""
                        chain_pem = chain.get("CertificateChain") or ""
                        row["definition"] = (cert + "\n" + chain_pem).strip()
                        row["definition_language"] = "text"
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "certificate_count": len(summaries),
        }
