"""Cognito — user pools, clients, identity pools and role mappings.

Identity-pool role mappings are a common pivot: the unauthenticated /
authenticated role ARNs handed out to browser tokens frequently carry
far more permission than the pool owner realises. Those ARNs are
surfaced on the identity-pool row so the IAM assumable-role analysis
can correlate against them.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult

_USER_POOL_PAGE = 60
_IDENTITY_POOL_PAGE = 60


class CognitoService(AwsService):
    service_name = "cognito"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("cognito-idp") as idp, ctx.client(
            "cognito-identity"
        ) as identity:
            user_pools = await _page(
                idp, "list_user_pools", "UserPools", MaxResults=_USER_POOL_PAGE
            )
            for pool in user_pools:
                row = await _user_pool_row(idp, pool, ctx.region, focused)
                result.resources.append(row)

            identity_pools = await _page(
                identity,
                "list_identity_pools",
                "IdentityPools",
                MaxResults=_IDENTITY_POOL_PAGE,
            )
            for pool in identity_pools:
                row = await _identity_pool_row(
                    identity, pool, ctx.region, focused
                )
                result.resources.append(row)

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "user_pool_count": len(user_pools),
            "identity_pool_count": len(identity_pools),
        }


async def _page(
    client: Any, op: str, key: str, **kwargs: Any
) -> list[dict[str, Any]]:
    """Uniform NextToken paginator for Cognito list operations."""
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["NextToken"] = next_token
        resp = await safe(getattr(client, op)(**call_kwargs))
        if not resp:
            break
        items.extend(resp.get(key, []) or [])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


async def _user_pool_row(
    idp: Any, pool: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    pool_id = pool.get("Id")
    row: dict[str, Any] = {
        "kind": "cognito-user-pool",
        "id": pool_id,
        "name": pool.get("Name"),
        "region": region,
        "status": pool.get("Status"),
        "last_modified": pool.get("LastModifiedDate"),
    }
    if not pool_id:
        return row
    if focused:
        detail_resp = await safe(idp.describe_user_pool(UserPoolId=pool_id))
        detail = (detail_resp or {}).get("UserPool") or {}
        row["arn"] = detail.get("Arn")
        row["mfa_configuration"] = detail.get("MfaConfiguration")
        row["account_recovery"] = detail.get("AccountRecoverySetting")
        row["password_policy"] = (
            detail.get("Policies") or {}
        ).get("PasswordPolicy")
        row["schema"] = [
            {"name": s.get("Name"), "required": s.get("Required"), "mutable": s.get("Mutable")}
            for s in detail.get("SchemaAttributes") or []
        ]
        lambda_triggers = detail.get("LambdaConfig") or {}
        if lambda_triggers:
            row["lambda_triggers"] = lambda_triggers
        row["email_configuration"] = detail.get("EmailConfiguration") or {}
        row["sms_configuration"] = detail.get("SmsConfiguration") or {}
        row["domain"] = detail.get("Domain")

        clients = await _page(
            idp,
            "list_user_pool_clients",
            "UserPoolClients",
            UserPoolId=pool_id,
            MaxResults=60,
        )
        client_details: list[dict[str, Any]] = []
        for client in clients:
            cid = client.get("ClientId")
            detail_client = await safe(
                idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=cid)
            )
            cd = (detail_client or {}).get("UserPoolClient") or client
            client_details.append(
                {
                    "id": cid,
                    "name": cd.get("ClientName"),
                    "has_client_secret": bool(cd.get("ClientSecret")),
                    "allowed_oauth_flows": cd.get("AllowedOAuthFlows") or [],
                    "allowed_oauth_scopes": cd.get("AllowedOAuthScopes") or [],
                    "callback_urls": cd.get("CallbackURLs") or [],
                    "logout_urls": cd.get("LogoutURLs") or [],
                    "supported_identity_providers": cd.get("SupportedIdentityProviders") or [],
                    "generate_secret": cd.get("ClientSecret") is not None,
                    "explicit_auth_flows": cd.get("ExplicitAuthFlows") or [],
                    "token_validity_days": cd.get("RefreshTokenValidity"),
                }
            )
        if client_details:
            row["clients"] = client_details

        identity_providers = await _page(
            idp,
            "list_identity_providers",
            "Providers",
            UserPoolId=pool_id,
            MaxResults=60,
        )
        if identity_providers:
            row["identity_providers"] = [
                {
                    "name": p.get("ProviderName"),
                    "type": p.get("ProviderType"),
                    "last_modified": p.get("LastModifiedDate"),
                }
                for p in identity_providers
            ]
    return row


async def _identity_pool_row(
    identity: Any, pool: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    pool_id = pool.get("IdentityPoolId")
    row: dict[str, Any] = {
        "kind": "cognito-identity-pool",
        "id": pool_id,
        "name": pool.get("IdentityPoolName"),
        "region": region,
    }
    if not pool_id:
        return row
    if focused:
        detail = await safe(identity.describe_identity_pool(IdentityPoolId=pool_id))
        if detail:
            row["allow_unauthenticated"] = detail.get(
                "AllowUnauthenticatedIdentities", False
            )
            row["allow_classic_flow"] = detail.get("AllowClassicFlow")
            row["supported_login_providers"] = detail.get(
                "SupportedLoginProviders"
            ) or {}
            row["openid_connect_providers"] = detail.get(
                "OpenIdConnectProviderARNs"
            ) or []
            row["cognito_identity_providers"] = [
                {
                    "provider_name": p.get("ProviderName"),
                    "client_id": p.get("ClientId"),
                    "server_side_token_check": p.get("ServerSideTokenCheck"),
                }
                for p in detail.get("CognitoIdentityProviders") or []
            ]
        roles_resp = await safe(
            identity.get_identity_pool_roles(IdentityPoolId=pool_id)
        )
        roles = (roles_resp or {}).get("Roles") or {}
        if roles:
            row["auth_role"] = roles.get("authenticated")
            row["unauth_role"] = roles.get("unauthenticated")
        mappings = (roles_resp or {}).get("RoleMappings") or {}
        if mappings:
            row["role_mappings"] = {
                key: {
                    "type": m.get("Type"),
                    "ambiguous_role_resolution": m.get("AmbiguousRoleResolution"),
                    "rules": (m.get("RulesConfiguration") or {}).get("Rules") or [],
                }
                for key, m in mappings.items()
            }
    return row
