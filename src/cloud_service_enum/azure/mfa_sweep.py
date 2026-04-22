"""Per-user MFA sweep for Azure AD / Entra ID.

Given a UPN + password, attempts an OAuth Resource Owner Password
Credentials (ROPC) flow against several well-known Microsoft endpoints
using the public Azure PowerShell client id. Each endpoint is classified
as one of:

    * **bypass**           — token issued, no MFA challenge (critical).
    * **mfa_required**     — credentials valid, MFA enforced (the desired
                             outcome from a defender's perspective).
    * **mfa_registration** — credentials valid, user has not yet
                             registered MFA factors.
    * **ca_blocked**       — Conditional Access blocked the auth.
    * **invalid_creds**    — wrong password.
    * **account_issue**    — account locked / disabled / not found.
    * **not_testable**     — resource doesn't trust the public client.
    * **error**            — anything else.

The full result document is returned as an :class:`EnumerationRun` so it
flows through the existing report writers (JSON, XLSX, …) unchanged.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from rich.panel import Panel

from cloud_service_enum.core.display import (
    render_config,
    render_identity,
    render_service,
    render_summary,
)
from cloud_service_enum.core.models import EnumerationRun, Provider, Scope, ServiceResult
from cloud_service_enum.core.output import get_console

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
# Azure PowerShell — public first-party client id with broad ROPC reach.
PUBLIC_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"

# (display name, scope) — kept short and reliable. Each scope uses the
# "/.default" form so we don't depend on consented per-scope grants.
DEFAULT_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("Microsoft Graph API", "https://graph.microsoft.com/.default"),
    ("Azure AD Graph (legacy)", "https://graph.windows.net/.default"),
    ("Azure Resource Manager", "https://management.azure.com/.default"),
    ("Azure Service Mgmt (legacy)", "https://management.core.windows.net/.default"),
    ("Office 365 Exchange Online", "https://outlook.office365.com/.default"),
    ("Office 365 Management API", "https://manage.office.com/.default"),
    ("Azure Key Vault", "https://vault.azure.net/.default"),
)


@dataclass
class MfaSweepScope:
    """Inputs for a per-user sweep."""

    upn: str
    password: str
    # ``organizations`` is the only multi-tenant endpoint Azure allows
    # ROPC over — ``common`` and ``consumers`` are rejected with
    # AADSTS90010. A specific tenant id always works too.
    tenant: str = "organizations"
    http_timeout_s: float = 20.0
    endpoints: tuple[tuple[str, str], ...] = DEFAULT_ENDPOINTS


# Map the most useful AADSTS codes onto a stable status label + message.
# Anything unrecognised falls through to ``error`` with the raw description.
_AADSTS_TABLE: dict[str, tuple[str, str]] = {
    "AADSTS50076": ("mfa_required", "MFA challenge required"),
    "AADSTS50158": ("mfa_required", "External MFA / federation challenge"),
    "AADSTS50079": ("mfa_registration", "MFA registration required"),
    "AADSTS50097": ("mfa_required", "Device authentication required"),
    "AADSTS50125": ("mfa_required", "Sign-in interrupted (password reset)"),
    "AADSTS530003": ("ca_blocked", "Blocked by Conditional Access (device)"),
    "AADSTS530005": ("ca_blocked", "Blocked by Conditional Access (compliance)"),
    "AADSTS53003": ("ca_blocked", "Blocked by Conditional Access"),
    "AADSTS50126": ("invalid_creds", "Invalid username or password"),
    "AADSTS50034": ("account_issue", "User does not exist"),
    "AADSTS50053": ("account_issue", "Account locked"),
    "AADSTS50057": ("account_issue", "Account disabled"),
    "AADSTS50055": ("account_issue", "Password expired"),
    "AADSTS50128": ("error", "Tenant not found"),
    "AADSTS50059": ("error", "No tenant id (use --tenant-id)"),
    "AADSTS700016": ("not_testable", "Resource doesn't trust the public client"),
    "AADSTS65001": ("not_testable", "Admin consent required"),
    "AADSTS9002313": ("error", "Invalid request body"),
    "AADSTS90010": ("not_testable", "ROPC unavailable on /common — pass --mfa-tenant"),
}


def _clean_description(text: str) -> str:
    """Drop Azure's trailing trace/correlation/timestamp noise."""
    if not text:
        return ""
    line = text.splitlines()[0]
    for marker in (" Trace ID:", " Correlation ID:", " Timestamp:"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx]
    return line.strip().rstrip(".")


# Status labels considered "successful authentication" for summary
# purposes — i.e. the password is valid even when MFA blocks the token.
_AUTHENTICATED_STATUSES = frozenset(
    {"bypass", "mfa_required", "mfa_registration", "ca_blocked"}
)


async def run_mfa_sweep(scope: MfaSweepScope) -> EnumerationRun:
    """Sweep ``scope.upn`` against every configured endpoint."""
    console = get_console()
    started = datetime.now(timezone.utc)

    cse_scope = Scope(
        provider=Provider.AZURE,
        services=["mfa-sweep"],
        max_concurrency=4,
        timeout_s=scope.http_timeout_s,
        iam_policy_bodies=False,
    )
    identity = {
        "provider": Provider.AZURE.value,
        "principal": scope.upn,
        "tenant_or_account": scope.tenant,
        "auth_method": "ROPC (Resource Owner Password Credentials)",
    }
    render_identity(console, identity)
    render_config(
        console,
        Provider.AZURE,
        cse_scope,
        extras={
            "Target user": scope.upn,
            "Tenant": scope.tenant,
            "Endpoints": len(scope.endpoints),
            "Public client": "Azure PowerShell (1950a258-…)",
        },
    )

    svc_started = datetime.now(timezone.utc)
    async with httpx.AsyncClient(
        timeout=scope.http_timeout_s,
        headers={"User-Agent": "cloud-service-enum/2.0 (+mfa-sweep)"},
    ) as http:
        sem = asyncio.Semaphore(4)
        results = await asyncio.gather(
            *[_probe(http, sem, scope, name, resource) for name, resource in scope.endpoints]
        )

    summary = _summarise(results)
    service = ServiceResult(
        provider=Provider.AZURE,
        service="mfa-sweep",
        started_at=svc_started,
        resources=results,
        cis_fields={
            "user": scope.upn,
            "tenant": scope.tenant,
            **summary,
        },
    )
    finished = datetime.now(timezone.utc)
    service.finished_at = finished
    service.duration_s = round((finished - svc_started).total_seconds(), 3)

    run = EnumerationRun(
        provider=Provider.AZURE,
        scope=cse_scope,
        identity=identity,
        services=[service],
        started_at=started,
        finished_at=finished,
        duration_s=round((finished - started).total_seconds(), 3),
    )
    render_service(console, service)
    _render_verdict(console, summary, scope.upn, results)
    render_summary(console, run)
    return run


# ---------------------------------------------------------------------------
# Probe + classify
# ---------------------------------------------------------------------------


async def _probe(
    http: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    scope: MfaSweepScope,
    name: str,
    resource: str,
) -> dict[str, Any]:
    url = TOKEN_URL.format(tenant=scope.tenant)
    body = {
        "client_id": PUBLIC_CLIENT_ID,
        "scope": resource,
        "grant_type": "password",
        "username": scope.upn,
        "password": scope.password,
    }
    async with sem:
        try:
            resp = await http.post(url, data=body)
        except Exception as exc:  # noqa: BLE001
            return _row(name, resource, "error", f"HTTP error: {exc}", None)

    if resp.status_code == 200:
        return _row(name, resource, "bypass", "Token issued without MFA challenge", None)

    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001
        payload = {}
    return _classify(name, resource, payload)


def _classify(name: str, resource: str, payload: dict[str, Any]) -> dict[str, Any]:
    desc = _clean_description(str(payload.get("error_description") or ""))
    code = _first_aadsts(desc) or ""
    status, message = _AADSTS_TABLE.get(
        code, ("error", desc[:200] if desc else "Unknown error")
    )
    return _row(name, resource, status, message, code or None)


def _first_aadsts(text: str) -> str | None:
    for token in text.split():
        bare = token.strip(":,.")
        if bare.startswith("AADSTS") and bare[6:].isdigit():
            return bare
    return None


def _row(
    name: str, resource: str, status: str, message: str, error_code: str | None
) -> dict[str, Any]:
    return {
        "kind": "endpoint",
        "id": name,
        "name": name,
        "resource": resource,
        "status": status,
        "mfa": _mfa_label(status),
        "message": message,
        "error_code": error_code or "-",
    }


def _mfa_label(status: str) -> str:
    if status == "bypass":
        return "no"
    if status in {"mfa_required", "mfa_registration"}:
        return "yes"
    if status == "ca_blocked":
        return "ca"
    return "-"


# ---------------------------------------------------------------------------
# Summary + verdict
# ---------------------------------------------------------------------------


def _summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    authed = sum(c for s, c in counts.items() if s in _AUTHENTICATED_STATUSES)
    return {
        "endpoints_tested": len(rows),
        "single_factor_access": counts.get("bypass", 0),
        "mfa_required": counts.get("mfa_required", 0) + counts.get("mfa_registration", 0),
        "ca_blocked": counts.get("ca_blocked", 0),
        "errors": sum(c for s, c in counts.items() if s in {"error", "not_testable"}),
        "credentials_valid": authed > 0,
        "account_issue": next(
            (r["message"] for r in rows if r["status"] == "account_issue"), None
        ),
        "bypassed_endpoints": [r["name"] for r in rows if r["status"] == "bypass"],
    }


def _render_verdict(
    console, summary: dict[str, Any], upn: str, rows: list[dict[str, Any]]
) -> None:
    """Print a coloured verdict panel after the per-endpoint table."""
    bypass = summary["bypassed_endpoints"]
    issue = summary["account_issue"]

    if issue:
        console.print(
            Panel(
                f"Account state for [bold]{upn}[/bold]: [warning]{issue}[/warning]\n"
                "Credentials may not have been validated against any endpoint.",
                title="account",
                border_style="warning",
            )
        )
        return

    if bypass:
        listing = "\n".join(f"  • {name}" for name in bypass)
        console.print(
            Panel(
                f"[error]Single-factor access available for [bold]{upn}[/bold] on "
                f"{len(bypass)} endpoint{'s' if len(bypass) != 1 else ''}:[/error]\n\n"
                f"{listing}\n\n"
                "These endpoints accepted the password without an MFA challenge.\n"
                "Treat as a high-priority finding — review Conditional Access "
                "and per-resource MFA enforcement.",
                title="MFA bypass detected",
                border_style="error",
            )
        )
        return

    if summary["credentials_valid"]:
        console.print(
            Panel(
                f"Credentials for [bold]{upn}[/bold] are valid, but every "
                "tested endpoint enforced MFA or Conditional Access.\n"
                "[success]No single-factor access exposure found.[/success]",
                title="verdict",
                border_style="success",
            )
        )
        return

    console.print(
        Panel(
            f"No endpoint accepted the credentials for [bold]{upn}[/bold].\n"
            "Either the password is wrong, the account doesn't exist, or "
            "every resource refused the public client used for ROPC.",
            title="verdict",
            border_style="warning",
        )
    )
