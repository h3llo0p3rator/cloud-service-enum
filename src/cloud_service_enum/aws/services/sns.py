"""SNS topics and subscriptions."""

from __future__ import annotations

import json
from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, collect_items, paginate, safe
from cloud_service_enum.core.models import ServiceResult


class SnsService(AwsService):
    service_name = "sns"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("sns") as sns:
            topics = collect_items(await paginate(sns, "list_topics"), "Topics")
            subs = collect_items(await paginate(sns, "list_subscriptions"), "Subscriptions")
            for t in topics:
                arn = t["TopicArn"]
                attrs = ((await safe(sns.get_topic_attributes(TopicArn=arn))) or {}).get(
                    "Attributes", {}
                )
                row: dict[str, Any] = {
                    "kind": "topic",
                    "id": arn,
                    "arn": arn,
                    "name": arn.split(":")[-1],
                    "region": ctx.region,
                    "encrypted": bool(attrs.get("KmsMasterKeyId")),
                    "kms_key": attrs.get("KmsMasterKeyId"),
                    "subscriptions": int(attrs.get("SubscriptionsConfirmed", 0) or 0),
                    "subscriptions_pending": int(
                        attrs.get("SubscriptionsPending", 0) or 0
                    ),
                    "fifo": attrs.get("FifoTopic") == "true",
                }
                _attach_policy(row, attrs.get("Policy"))
                result.resources.append(row)
        for s in subs:
            result.resources.append(
                {
                    "kind": "subscription",
                    "id": s.get("SubscriptionArn"),
                    "region": ctx.region,
                    "topic": s.get("TopicArn"),
                    "protocol": s.get("Protocol"),
                    "endpoint": s.get("Endpoint"),
                }
            )
        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "topic_count": len(topics),
            "unencrypted_topics": sum(
                1 for r in result.resources if r.get("kind") == "topic" and not r.get("encrypted")
            ),
            "topics_open_to_world": sum(
                1
                for r in result.resources
                if r.get("kind") == "topic" and _is_world_open(r.get("policy_document"))
            ),
        }


def _attach_policy(row: dict[str, Any], body: Any) -> None:
    if not isinstance(body, str) or not body:
        return
    try:
        row["policy_document"] = json.loads(body)
    except ValueError:
        row["policy_document"] = {"_raw": body}


def _is_world_open(policy: Any) -> bool:
    if not isinstance(policy, dict):
        return False
    for stmt in policy.get("Statement", []) or []:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*" or (
            isinstance(principal, dict) and "*" in (principal.get("AWS") or [])
        ):
            return True
    return False
