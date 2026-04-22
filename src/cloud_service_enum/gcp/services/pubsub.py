"""Pub/Sub topics and subscriptions."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class PubSubService(GcpService):
    service_name = "pubsub"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import pubsub_v1
        except ImportError:
            missing_sdk(result, "google-cloud-pubsub")
            return
        publisher = pubsub_v1.PublisherClient(credentials=credentials)
        subscriber = pubsub_v1.SubscriberClient(credentials=credentials)
        topics = safe_list(publisher.list_topics(request={"project": f"projects/{project_id}"}))
        subs = safe_list(subscriber.list_subscriptions(request={"project": f"projects/{project_id}"}))
        focused = self.is_focused_on()
        for t in topics:
            row = {
                "kind": "topic",
                "id": t.name,
                "name": t.name.split("/")[-1],
                "project": project_id,
                "kms_key": t.kms_key_name or None,
                "message_retention_duration": str(t.message_retention_duration) if t.message_retention_duration else None,
                "schema_settings": t.schema_settings.schema if t.schema_settings else None,
            }
            if focused:
                try:
                    iam = publisher.get_iam_policy(request={"resource": t.name})
                    row["role_bindings"] = [
                        {"role": b.role, "members": list(b.members)}
                        for b in iam.bindings
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(row)
        for s in subs:
            result.resources.append(
                {
                    "kind": "subscription",
                    "id": s.name,
                    "name": s.name.split("/")[-1],
                    "project": project_id,
                    "topic": s.topic,
                    "ack_deadline_s": s.ack_deadline_seconds,
                    "message_retention_duration": str(s.message_retention_duration) if s.message_retention_duration else None,
                    "dead_letter_topic": s.dead_letter_policy.dead_letter_topic if s.dead_letter_policy else None,
                }
            )
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "topic_count": len(topics),
            "subscription_count": len(subs),
            "topics_with_cmek": sum(1 for t in topics if t.kms_key_name),
        }
