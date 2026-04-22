"""SQS queues and attributes."""

from __future__ import annotations

import json
from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class SqsService(AwsService):
    service_name = "sqs"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("sqs") as sqs:
            resp = await safe(sqs.list_queues())
            urls = (resp or {}).get("QueueUrls") or []
            for url in urls:
                attrs = await safe(sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"]))
                a = (attrs or {}).get("Attributes", {})
                row: dict[str, Any] = {
                    "kind": "queue",
                    "id": url,
                    "name": url.rsplit("/", 1)[-1],
                    "region": ctx.region,
                    "arn": a.get("QueueArn"),
                    "kms_key": a.get("KmsMasterKeyId"),
                    "encrypted": bool(
                        a.get("KmsMasterKeyId") or a.get("SqsManagedSseEnabled") == "true"
                    ),
                    "visibility_timeout": a.get("VisibilityTimeout"),
                    "max_receive_count": a.get("RedrivePolicy"),
                    "fifo": a.get("FifoQueue") == "true",
                }
                _attach_policy(row, a.get("Policy"))
                if focused and a.get("QueueArn"):
                    sources = await safe(
                        sqs.list_dead_letter_source_queues(QueueUrl=url)
                    )
                    if sources:
                        row["dlq_source_queues"] = sources.get("queueUrls") or []
                result.resources.append(row)
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "queue_count": len(urls),
            "unencrypted_queues": sum(
                1 for r in result.resources if r.get("kind") == "queue" and not r.get("encrypted")
            ),
        }


def _attach_policy(row: dict[str, Any], body: Any) -> None:
    if not isinstance(body, str) or not body:
        return
    try:
        row["policy_document"] = json.loads(body)
    except ValueError:
        row["policy_document"] = {"_raw": body}
