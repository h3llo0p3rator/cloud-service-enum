"""STS identity check — returns caller identity and session metadata."""

from __future__ import annotations

from cloud_service_enum.aws.base import AwsService, ServiceContext
from cloud_service_enum.core.models import ServiceResult


class StsService(AwsService):
    service_name = "sts"
    is_regional = False

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("sts") as sts:
            ident = await sts.get_caller_identity()
        result.resources.append(
            {
                "kind": "caller-identity",
                "id": ident["Arn"],
                "name": ident["UserId"],
                "account": ident["Account"],
            }
        )
        result.cis_fields = {"account_id": ident["Account"], "caller_arn": ident["Arn"]}
