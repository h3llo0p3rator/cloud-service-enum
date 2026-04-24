"""API Gateway — REST (v1) + HTTP/WebSocket (v2) APIs.

Invoke URLs, resource policies, authorizers and integration target
ARNs are captured so an operator can cross-reference authenticated
results with the unauthenticated probe scan
(``cse aws unauth api-gateway``).
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


class ApiGatewayService(AwsService):
    service_name = "apigateway"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("apigateway") as v1, ctx.client(
            "apigatewayv2"
        ) as v2:
            rest_apis = collect_items(
                await paginate(v1, "get_rest_apis"), "items"
            )
            for api in rest_apis:
                result.resources.append(
                    await _rest_api_row(v1, api, ctx.region, focused)
                )

            http_apis = await _list_http_apis(v2)
            for api in http_apis:
                result.resources.append(
                    await _http_api_row(v2, api, ctx.region, focused)
                )

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "rest_api_count": len(rest_apis),
            "http_api_count": len(http_apis),
        }


async def _rest_api_row(
    client: Any, api: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    api_id = api.get("id")
    endpoint_config = api.get("endpointConfiguration") or {}
    row: dict[str, Any] = {
        "kind": "rest-api",
        "id": api_id,
        "name": api.get("name"),
        "region": region,
        "description": api.get("description"),
        "endpoint_types": endpoint_config.get("types") or [],
        "api_key_source": api.get("apiKeySource"),
        "disable_execute_api_endpoint": api.get("disableExecuteApiEndpoint", False),
        "created_at": api.get("createdDate"),
    }
    if api_id:
        row["invoke_base"] = f"https://{api_id}.execute-api.{region}.amazonaws.com"
    if not focused or not api_id:
        return row

    stages_resp = await safe(client.get_stages(restApiId=api_id))
    stages = [
        {
            "name": s.get("stageName"),
            "deployment": s.get("deploymentId"),
            "tracing": s.get("tracingEnabled"),
            "variables": s.get("variables") or {},
            "invoke_url": f"{row['invoke_base']}/{s.get('stageName')}"
            if row.get("invoke_base") and s.get("stageName")
            else None,
        }
        for s in (stages_resp or {}).get("item", []) or []
    ]
    if stages:
        row["stages"] = stages

    resources = collect_items(
        await paginate(client, "get_resources", restApiId=api_id, embed=["methods"]),
        "items",
    )
    methods: list[dict[str, Any]] = []
    for res in resources:
        path = res.get("path")
        for name, method in (res.get("resourceMethods") or {}).items():
            methods.append(
                {
                    "path": path,
                    "method": name,
                    "auth_type": method.get("authorizationType"),
                    "authorizer_id": method.get("authorizerId"),
                    "api_key_required": method.get("apiKeyRequired", False),
                }
            )
    if methods:
        row["methods"] = methods

    authorizers_resp = await safe(client.get_authorizers(restApiId=api_id))
    authorizers = [
        {
            "id": a.get("id"),
            "name": a.get("name"),
            "type": a.get("type"),
            "provider_arns": a.get("providerARNs") or [],
            "authorizer_uri": a.get("authorizerUri"),
            "identity_source": a.get("identitySource"),
        }
        for a in (authorizers_resp or {}).get("items", []) or []
    ]
    if authorizers:
        row["authorizers"] = authorizers

    api_keys_resp = await safe(
        client.get_api_keys(includeValues=False, limit=100)
    )
    api_keys = [
        {
            "id": k.get("id"),
            "name": k.get("name"),
            "enabled": k.get("enabled"),
            "created": k.get("createdDate"),
        }
        for k in (api_keys_resp or {}).get("items", []) or []
    ]
    if api_keys:
        row["api_keys"] = api_keys

    usage_plans_resp = await safe(client.get_usage_plans(limit=100))
    usage_plans = [
        {
            "id": p.get("id"),
            "name": p.get("name"),
            "api_stages": p.get("apiStages") or [],
            "throttle": p.get("throttle") or {},
            "quota": p.get("quota") or {},
        }
        for p in (usage_plans_resp or {}).get("items", []) or []
    ]
    if usage_plans:
        row["usage_plans"] = usage_plans

    policy_text = api.get("policy")
    if policy_text:
        row["policy_document"] = _decode_policy(policy_text)
    return row


async def _list_http_apis(client: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = await safe(client.get_apis(**kwargs))
        if not resp:
            break
        items.extend(resp.get("Items", []) or [])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


async def _http_api_row(
    client: Any, api: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    api_id = api.get("ApiId")
    row: dict[str, Any] = {
        "kind": "http-api",
        "id": api_id,
        "arn": api.get("ApiArn"),
        "name": api.get("Name"),
        "region": region,
        "protocol": api.get("ProtocolType"),
        "api_endpoint": api.get("ApiEndpoint"),
        "cors_configuration": api.get("CorsConfiguration") or {},
        "disable_execute_api_endpoint": api.get("DisableExecuteApiEndpoint", False),
        "route_selection_expression": api.get("RouteSelectionExpression"),
        "version": api.get("Version"),
    }
    if not focused or not api_id:
        return row

    routes = await _page_v2(client, "get_routes", ApiId=api_id)
    if routes:
        row["routes"] = [
            {
                "route_key": r.get("RouteKey"),
                "target": r.get("Target"),
                "authorization_type": r.get("AuthorizationType"),
                "authorizer_id": r.get("AuthorizerId"),
            }
            for r in routes
        ]

    authorizers = await _page_v2(client, "get_authorizers", ApiId=api_id)
    if authorizers:
        row["authorizers"] = [
            {
                "id": a.get("AuthorizerId"),
                "name": a.get("Name"),
                "type": a.get("AuthorizerType"),
                "identity_source": a.get("IdentitySource") or [],
                "authorizer_uri": a.get("AuthorizerUri"),
                "jwt_configuration": a.get("JwtConfiguration") or {},
            }
            for a in authorizers
        ]

    integrations = await _page_v2(client, "get_integrations", ApiId=api_id)
    if integrations:
        row["integrations"] = [
            {
                "id": i.get("IntegrationId"),
                "type": i.get("IntegrationType"),
                "method": i.get("IntegrationMethod"),
                "uri": i.get("IntegrationUri"),
                "subtype": i.get("IntegrationSubtype"),
                "payload_format": i.get("PayloadFormatVersion"),
                "credentials": i.get("CredentialsArn"),
            }
            for i in integrations
        ]

    stages = await _page_v2(client, "get_stages", ApiId=api_id)
    if stages:
        row["stages"] = [
            {
                "name": s.get("StageName"),
                "auto_deploy": s.get("AutoDeploy"),
                "default_route_settings": s.get("DefaultRouteSettings") or {},
                "stage_variables": s.get("StageVariables") or {},
            }
            for s in stages
        ]
    return row


async def _page_v2(client: Any, op: str, **kwargs: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["NextToken"] = next_token
        resp = await safe(getattr(client, op)(**call_kwargs))
        if not resp:
            break
        items.extend(resp.get("Items", []) or [])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


def _decode_policy(policy_text: str) -> Any:
    # REST APIs return the policy with escaped double-quotes (`\"`)
    # because the gateway stores it that way. Undo the escaping before
    # passing it to ``json.loads``.
    try:
        return json.loads(policy_text.replace('\\"', '"'))
    except ValueError:
        try:
            return json.loads(policy_text)
        except ValueError:
            return {"_raw": policy_text}
