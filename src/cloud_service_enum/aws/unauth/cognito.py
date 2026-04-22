"""Cognito ID extraction + safe public-API probes.

Pulls user-pool / identity-pool / app-client IDs out of crawled HTML and
JS bundles, then optionally exercises a handful of unauthenticated AWS
endpoints to characterise what was found:

* ``GetId``        — does the identity pool hand out unauthenticated
                     identities?
* ``InitiateAuth`` — what auth flows does the user pool accept, and is
                     the discovered ``ClientId`` valid?
* ``SignUp``       — is self-registration enabled? (opt-in; sends a
                     deliberately invalid request — no user created.)

All probes use plain :mod:`httpx` against the public AWS service
endpoints; nothing in this module imports an AWS SDK or requires
credentials.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

import httpx

from cloud_service_enum.aws.unauth.crawler import FetchedPage

USER_POOL_RE = re.compile(r"\b([a-z]{2}-[a-z]+-\d)_([A-Za-z0-9]{8,30})\b")
IDENTITY_POOL_RE = re.compile(
    r"\b([a-z]{2}-[a-z]+-\d):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"
)
CLIENT_ID_RE = re.compile(
    r"""(?:userPoolWebClientId|appClientId|ClientId|clientId|client_id)\s*[:=]\s*["']([a-z0-9]{20,52})["']""",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CognitoHit:
    """One pool/client id discovered in a crawled page."""

    kind: str  # "user_pool" | "identity_pool" | "client_id"
    value: str
    region: str
    first_seen_url: str


@dataclass
class ProbeResult:
    """Outcome of a single API probe."""

    name: str
    status: str  # "ok" | "denied" | "error" | "skipped"
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


def extract(pages: list[FetchedPage]) -> list[CognitoHit]:
    """Return deduplicated Cognito IDs across every page body."""
    hits: dict[tuple[str, str], CognitoHit] = {}
    candidate_clients: dict[str, str] = {}

    def _add(kind: str, value: str, region: str, url: str) -> None:
        key = (kind, value)
        if key not in hits:
            hits[key] = CognitoHit(
                kind=kind, value=value, region=region, first_seen_url=url
            )

    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in USER_POOL_RE.finditer(body):
            region, suffix = match.group(1), match.group(2)
            _add("user_pool", f"{region}_{suffix}", region, page.url)
        for match in IDENTITY_POOL_RE.finditer(body):
            region, guid = match.group(1), match.group(2)
            _add("identity_pool", f"{region}:{guid}", region, page.url)
        for match in CLIENT_ID_RE.finditer(body):
            candidate_clients.setdefault(match.group(1), page.url)

    pool_region = next(
        (h.region for h in hits.values() if h.kind == "user_pool"),
        next((h.region for h in hits.values() if h.kind == "identity_pool"), ""),
    )
    for client_id, url in candidate_clients.items():
        _add("client_id", client_id, pool_region, url)

    return list(hits.values())


def region_of(pool_id: str) -> str:
    """Return the AWS region prefix encoded in a pool id."""
    if "_" in pool_id:
        return pool_id.split("_", 1)[0]
    if ":" in pool_id:
        return pool_id.split(":", 1)[0]
    return ""


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


async def probe_get_id(
    client: httpx.AsyncClient, identity_pool_id: str
) -> ProbeResult:
    """Call ``GetId`` against the identity pool to test unauth access."""
    region = region_of(identity_pool_id)
    if not region:
        return ProbeResult("GetId", "skipped", "no region in pool id")
    url = f"https://cognito-identity.{region}.amazonaws.com/"
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AWSCognitoIdentityService.GetId",
    }
    body = json.dumps({"IdentityPoolId": identity_pool_id})
    payload, error = await _post(client, url, headers, body)
    if error is not None:
        return ProbeResult("GetId", "error", error)
    if "IdentityId" in payload:
        return ProbeResult(
            "GetId",
            "ok",
            "Unauthenticated identities are enabled",
            detail={"identity_id": payload["IdentityId"]},
        )
    aws_type = _aws_error(payload)
    if aws_type == "NotAuthorizedException":
        return ProbeResult("GetId", "denied", "Unauth identities not enabled")
    return ProbeResult(
        "GetId",
        "denied",
        f"{aws_type or 'Unknown'}: {payload.get('message', '')[:200]}",
    )


async def probe_initiate_auth(
    client: httpx.AsyncClient, user_pool_id: str, client_id: str
) -> ProbeResult:
    """Probe ``InitiateAuth`` to learn supported flows + validate the client."""
    region = region_of(user_pool_id)
    if not region:
        return ProbeResult("InitiateAuth", "skipped", "no region in pool id")
    url = f"https://cognito-idp.{region}.amazonaws.com/"
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
    }
    body = json.dumps(
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client_id,
            "AuthParameters": {
                "USERNAME": f"cse-probe-{secrets.token_hex(4)}@example.invalid",
                "PASSWORD": secrets.token_urlsafe(16),
            },
        }
    )
    payload, error = await _post(client, url, headers, body)
    if error is not None:
        return ProbeResult("InitiateAuth", "error", error)
    aws_type = _aws_error(payload) or "Unknown"
    msg = payload.get("message", "")
    flows = _classify_initiate_auth(aws_type, msg)
    return ProbeResult(
        "InitiateAuth",
        "ok" if flows["client_id_valid"] else "denied",
        flows["summary"],
        detail=flows,
    )


async def probe_signup(
    client: httpx.AsyncClient, user_pool_id: str, client_id: str
) -> ProbeResult:
    """Probe ``SignUp`` with a deliberately invalid password."""
    region = region_of(user_pool_id)
    if not region:
        return ProbeResult("SignUp", "skipped", "no region in pool id")
    url = f"https://cognito-idp.{region}.amazonaws.com/"
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AWSCognitoIdentityProviderService.SignUp",
    }
    body = json.dumps(
        {
            "ClientId": client_id,
            "Username": f"cse-probe-{secrets.token_hex(4)}@example.invalid",
            "Password": "a",  # intentionally too short — SignUp will reject before persisting
        }
    )
    payload, error = await _post(client, url, headers, body)
    if error is not None:
        return ProbeResult("SignUp", "error", error)
    aws_type = _aws_error(payload) or "Unknown"
    msg = payload.get("message", "")
    summary, signup_enabled = _classify_signup(aws_type, msg)
    return ProbeResult(
        "SignUp",
        "ok" if signup_enabled else "denied",
        summary,
        detail={"signup_enabled": signup_enabled, "aws_error": aws_type},
    )


# ---------------------------------------------------------------------------
# HTTP / classification helpers
# ---------------------------------------------------------------------------


async def _post(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    body: str,
) -> tuple[dict[str, Any], str | None]:
    try:
        resp = await client.post(url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        return {}, f"{exc.__class__.__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        return {}, f"{exc.__class__.__name__}: {exc}"
    try:
        payload = resp.json()
    except (ValueError, json.JSONDecodeError):
        return {}, f"non-JSON response (HTTP {resp.status_code})"
    if not isinstance(payload, dict):
        return {}, f"unexpected response shape (HTTP {resp.status_code})"
    return payload, None


def _aws_error(payload: dict[str, Any]) -> str | None:
    raw = payload.get("__type") or payload.get("type")
    if not raw:
        return None
    # Format is usually ``com.amazon.coral.service#NotAuthorizedException``.
    if "#" in raw:
        return raw.rsplit("#", 1)[1]
    return raw


def _classify_initiate_auth(aws_type: str, message: str) -> dict[str, Any]:
    """Translate an InitiateAuth response into a structured fingerprint."""
    msg_lower = (message or "").lower()
    flow_disabled = "user_password_auth flow not enabled" in msg_lower
    invalid_client = aws_type in {"ResourceNotFoundException", "InvalidParameterException"} and (
        "client" in msg_lower and "does not exist" in msg_lower
    )
    if invalid_client:
        return {
            "client_id_valid": False,
            "user_password_auth_enabled": None,
            "summary": "ClientId not recognised by user pool",
        }
    if flow_disabled:
        return {
            "client_id_valid": True,
            "user_password_auth_enabled": False,
            "summary": "ClientId valid; USER_PASSWORD_AUTH flow disabled",
        }
    if aws_type in {"NotAuthorizedException", "UserNotFoundException"}:
        return {
            "client_id_valid": True,
            "user_password_auth_enabled": True,
            "summary": (
                "ClientId valid; USER_PASSWORD_AUTH accepted "
                f"({aws_type} for bogus user)"
            ),
        }
    return {
        "client_id_valid": True,
        "user_password_auth_enabled": None,
        "summary": f"{aws_type or 'response'}: {(message or '')[:160]}",
    }


def _classify_signup(aws_type: str, message: str) -> tuple[str, bool]:
    """Translate a SignUp response into ``(summary, signup_enabled)``."""
    msg_lower = (message or "").lower()
    if aws_type == "InvalidPasswordException":
        return ("Self-registration enabled (password complaint received)", True)
    if aws_type == "InvalidParameterException":
        if "password" in msg_lower:
            return ("Self-registration enabled (password complaint received)", True)
        return ("Self-registration likely enabled (schema validation triggered)", True)
    if aws_type == "NotAuthorizedException" and "signup is not permitted" in msg_lower:
        return ("Self-registration disabled by pool policy", False)
    if aws_type == "ResourceNotFoundException":
        return ("ClientId not recognised by user pool", False)
    return (f"{aws_type or 'response'}: {(message or '')[:160]}", False)
