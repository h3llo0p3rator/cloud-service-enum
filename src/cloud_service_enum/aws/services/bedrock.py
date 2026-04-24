"""Bedrock — agents, aliases, guardrails and knowledge-base data sources.

Agent *instruction* text is the interesting attacker artefact: it often
encodes prompt-injection mitigations, tool allow-lists and downstream
Lambda ARNs. Knowledge-base data sources expose the underlying S3
buckets, which the S3 scanner can then cross-reference.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult


class BedrockService(AwsService):
    service_name = "bedrock"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("bedrock-agent") as agent_client, ctx.client(
            "bedrock"
        ) as bedrock_client:
            agents = await _list_all(agent_client, "list_agents", "agentSummaries")
            for agent in agents:
                row = await _agent_row(
                    agent_client, agent, ctx.region, focused
                )
                result.resources.append(row)

            guardrails = await _list_all(
                bedrock_client, "list_guardrails", "guardrails"
            )
            for guardrail in guardrails:
                row = await _guardrail_row(
                    bedrock_client, guardrail, ctx.region, focused
                )
                result.resources.append(row)

            kbs = await _list_all(
                agent_client, "list_knowledge_bases", "knowledgeBaseSummaries"
            )
            for kb in kbs:
                row = await _knowledge_base_row(
                    agent_client, kb, ctx.region, focused
                )
                result.resources.append(row)

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "agent_count": len(agents),
            "guardrail_count": len(guardrails),
            "knowledge_base_count": len(kbs),
        }


async def _list_all(client: Any, op: str, key: str) -> list[dict[str, Any]]:
    """Drive a paginator even if the operation lacks one in botocore."""
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = await safe(getattr(client, op)(**kwargs))
        if not resp:
            break
        items.extend(resp.get(key, []) or [])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


async def _agent_row(
    client: Any, agent: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    agent_id = agent.get("agentId")
    row: dict[str, Any] = {
        "kind": "bedrock-agent",
        "id": agent_id,
        "arn": agent.get("agentArn") or agent.get("arn"),
        "name": agent.get("agentName"),
        "region": region,
        "status": agent.get("agentStatus"),
        "description": agent.get("description"),
        "updated_at": agent.get("updatedAt"),
    }
    if focused and agent_id:
        details = await safe(client.get_agent(agentId=agent_id))
        agent_detail = (details or {}).get("agent") or {}
        row["foundation_model"] = agent_detail.get("foundationModel")
        row["idle_session_ttl"] = agent_detail.get("idleSessionTTLInSeconds")
        row["agent_role"] = agent_detail.get("agentResourceRoleArn")
        instruction = agent_detail.get("instruction")
        if instruction:
            row["definition"] = instruction
            row["definition_language"] = "text"

        aliases = await _list_all(
            _WithKwargs(client, "list_agent_aliases", agentId=agent_id),
            "call",
            "agentAliasSummaries",
        )
        if aliases:
            row["aliases"] = [
                {
                    "id": a.get("agentAliasId"),
                    "name": a.get("agentAliasName"),
                    "status": a.get("agentAliasStatus"),
                    "updated_at": a.get("updatedAt"),
                }
                for a in aliases
            ]
    return row


async def _guardrail_row(
    client: Any, guardrail: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    identifier = guardrail.get("id") or guardrail.get("arn")
    row: dict[str, Any] = {
        "kind": "bedrock-guardrail",
        "id": identifier,
        "arn": guardrail.get("arn"),
        "name": guardrail.get("name"),
        "region": region,
        "status": guardrail.get("status"),
        "version": guardrail.get("version"),
        "updated_at": guardrail.get("updatedAt"),
    }
    if focused and identifier:
        detail = await safe(
            client.get_guardrail(guardrailIdentifier=identifier)
        )
        if detail:
            row["content_filters"] = [
                {
                    "type": f.get("type"),
                    "input_strength": f.get("inputStrength"),
                    "output_strength": f.get("outputStrength"),
                }
                for f in (detail.get("contentPolicy") or {}).get("filters", [])
            ]
            row["topic_filters"] = [
                {
                    "name": t.get("name"),
                    "type": t.get("type"),
                    "examples": t.get("examples") or [],
                }
                for t in (detail.get("topicPolicy") or {}).get("topics", [])
            ]
            row["word_policy"] = {
                "words": [w.get("text") for w in (detail.get("wordPolicy") or {}).get("words", [])],
                "managed": [m.get("type") for m in (detail.get("wordPolicy") or {}).get("managedWordLists", [])],
            }
    return row


async def _knowledge_base_row(
    client: Any, kb: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    kb_id = kb.get("knowledgeBaseId")
    row: dict[str, Any] = {
        "kind": "bedrock-kb",
        "id": kb_id,
        "name": kb.get("name"),
        "region": region,
        "status": kb.get("status"),
        "updated_at": kb.get("updatedAt"),
    }
    if focused and kb_id:
        detail = await safe(client.get_knowledge_base(knowledgeBaseId=kb_id))
        body = (detail or {}).get("knowledgeBase") or {}
        row["arn"] = body.get("knowledgeBaseArn")
        row["role_arn"] = body.get("roleArn")
        row["type"] = (body.get("knowledgeBaseConfiguration") or {}).get("type")

        ds_items = await _list_all(
            _WithKwargs(client, "list_data_sources", knowledgeBaseId=kb_id),
            "call",
            "dataSourceSummaries",
        )
        data_sources: list[dict[str, Any]] = []
        for ds in ds_items:
            ds_id = ds.get("dataSourceId")
            entry: dict[str, Any] = {
                "id": ds_id,
                "name": ds.get("name"),
                "status": ds.get("status"),
            }
            if ds_id:
                ds_detail = await safe(
                    client.get_data_source(
                        knowledgeBaseId=kb_id, dataSourceId=ds_id
                    )
                )
                cfg = ((ds_detail or {}).get("dataSource") or {}).get(
                    "dataSourceConfiguration"
                ) or {}
                s3 = cfg.get("s3Configuration") or {}
                if s3:
                    entry["s3_bucket"] = s3.get("bucketArn")
                    entry["s3_prefixes"] = s3.get("inclusionPrefixes") or []
            data_sources.append(entry)
        if data_sources:
            row["data_sources"] = data_sources
    return row


class _WithKwargs:
    """Binds default kwargs onto a client operation so ``_list_all`` can page it."""

    def __init__(self, client: Any, op: str, **kwargs: Any) -> None:
        self._client = client
        self._op = op
        self._kwargs = kwargs

    def call(self, **extra: Any) -> Any:
        return getattr(self._client, self._op)(**self._kwargs, **extra)
