"""Active ``sts:AssumeRole`` probing against a list of candidate ARNs.

Given a set of target role ARNs (supplied via ``--role-arn`` flags or a
file), attempt :meth:`sts.assume_role` against each and classify the
outcome. This is the ground-truth complement to the IAM caller-identity
introspection: IAM introspection tells the auditor what the *policies*
say is assumable, this module tells them what actually *works* right
now, including cross-account trust-policy effects the caller has no
read access to.

The probe is read-only — a successful assume-role just returns short
lived credentials that are never used for anything. We throw them away
after recording the returned principal ARN and expiry.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from cloud_service_enum.aws.auth import AwsAuthConfig, AwsAuthenticator
from cloud_service_enum.core.display import render_service, render_summary
from cloud_service_enum.core.errors import AuthenticationError
from cloud_service_enum.core.models import EnumerationRun, Provider, Scope, ServiceResult
from cloud_service_enum.core.output import Console, get_console

# Arn shape: arn:aws:iam::<account>:role/<path>/<name>
_ROLE_ARN_RE = re.compile(
    r"^arn:(?P<partition>aws|aws-cn|aws-us-gov):iam::(?P<account>\d{12}):role(?:/.+)?$"
)

_STATUS_STYLES: dict[str, str] = {
    "success": "success",
    "access_denied": "warning",
    "trust_denied": "warning",
    "no_such_role": "muted",
    "malformed": "muted",
    "throttled": "warning",
    "error": "error",
}


@dataclass
class ProbeAssumeScope:
    """Inputs for ``cse aws probe-assume``."""

    role_arns: tuple[str, ...]
    external_id: str | None = None
    session_name: str = "cse-probe-assume"
    duration_seconds: int = 900
    max_concurrency: int = 10
    timeout_s: float = 30.0
    # Credentials (mirrors ``cse aws enumerate``)
    profile: str | None = None
    region: str | None = None
    access_key: str | None = None
    secret_key: str | None = None
    session_token: str | None = None
    role_arn: str | None = None  # pre-hop assume before probing
    web_identity_token_file: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssumeAttempt:
    """Result of probing a single candidate ARN."""

    role_arn: str
    status: str
    error_code: str = ""
    error_message: str = ""
    assumed_arn: str = ""
    session_expiration: str = ""


def load_role_arns(sources: tuple[str, ...], *, path: Path | None) -> list[str]:
    """Normalise CLI role-arn inputs into a de-duplicated ordered list."""
    collected: list[str] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        entry = raw.strip()
        if not entry or entry.startswith("#") or entry in seen:
            return
        seen.add(entry)
        collected.append(entry)

    for raw in sources:
        for piece in raw.split(","):
            _add(piece)
    if path is not None:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            _add(line)
    return collected


async def run_probe_assume(scope: ProbeAssumeScope) -> EnumerationRun:
    """Probe every candidate ARN in ``scope.role_arns`` concurrently."""
    console = get_console()
    started = datetime.now(timezone.utc)
    cse_scope = Scope(
        provider=Provider.AWS,
        services=["probe-assume"],
        max_concurrency=scope.max_concurrency,
        timeout_s=scope.timeout_s,
        iam_policy_bodies=False,
    )

    cfg = AwsAuthConfig(
        profile=scope.profile,
        region=scope.region,
        access_key=scope.access_key,
        secret_key=scope.secret_key,
        session_token=scope.session_token,
        role_arn=scope.role_arn,
        external_id=scope.external_id if scope.role_arn else None,
        web_identity_token_file=scope.web_identity_token_file,
    )
    auth = AwsAuthenticator(cfg)

    try:
        identity_summary = await auth.test()
    except Exception as exc:  # noqa: BLE001
        await auth.close()
        raise AuthenticationError(f"aws: {exc}") from exc

    identity = identity_summary.model_dump()

    from cloud_service_enum.core.display import render_config, render_identity

    render_identity(console, identity)
    render_config(
        console,
        Provider.AWS,
        cse_scope,
        extras={
            "Candidate ARNs": len(scope.role_arns),
            "Session name": scope.session_name,
            "External ID": "set" if scope.external_id else "unset",
            "Duration": f"{scope.duration_seconds}s",
        },
    )

    svc_started = datetime.now(timezone.utc)
    try:
        attempts = await _run_attempts(auth, scope)
    finally:
        await auth.close()

    resources = [_attempt_to_row(a) for a in attempts]
    cis_fields = _summarise(attempts)
    service = ServiceResult(
        provider=Provider.AWS,
        service="probe-assume",
        started_at=svc_started,
        resources=resources,
        cis_fields=cis_fields,
    )
    finished = datetime.now(timezone.utc)
    service.finished_at = finished
    service.duration_s = round((finished - svc_started).total_seconds(), 3)

    run = EnumerationRun(
        provider=Provider.AWS,
        scope=cse_scope,
        identity=identity,
        services=[service],
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        duration_s=round((datetime.now(timezone.utc) - started).total_seconds(), 3),
    )

    render_service(console, service)
    _render_verdict(console, attempts)
    render_summary(console, run)
    return run


async def _run_attempts(
    auth: AwsAuthenticator, scope: ProbeAssumeScope
) -> list[AssumeAttempt]:
    """Fan out one probe per candidate ARN under a shared semaphore."""
    session = await auth.session()
    sem = asyncio.Semaphore(scope.max_concurrency)

    async def _one(arn: str) -> AssumeAttempt:
        async with sem:
            return await _probe_one(session, scope, arn)

    async with asyncio.TaskGroup() as tg:
        tasks = [tg.create_task(_one(arn)) for arn in scope.role_arns]
    return [t.result() for t in tasks]


async def _probe_one(
    session: Any, scope: ProbeAssumeScope, arn: str
) -> AssumeAttempt:
    """Call ``sts:AssumeRole`` once and classify the outcome."""
    if not _ROLE_ARN_RE.match(arn):
        return AssumeAttempt(
            role_arn=arn,
            status="malformed",
            error_message="Not a valid IAM role ARN (expected arn:aws:iam::<account>:role/...).",
        )

    kwargs: dict[str, Any] = {
        "RoleArn": arn,
        "RoleSessionName": scope.session_name,
        "DurationSeconds": max(900, min(scope.duration_seconds, 3600)),
    }
    if scope.external_id:
        kwargs["ExternalId"] = scope.external_id

    try:
        async with session.client(
            "sts", region_name=scope.region or "us-east-1"
        ) as sts:
            resp = await sts.assume_role(**kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        return AssumeAttempt(
            role_arn=arn,
            status=_classify_client_error(code, message),
            error_code=code,
            error_message=message,
        )
    except BotoCoreError as exc:
        return AssumeAttempt(
            role_arn=arn,
            status="error",
            error_code=type(exc).__name__,
            error_message=str(exc),
        )

    creds = resp.get("Credentials", {}) or {}
    assumed = resp.get("AssumedRoleUser", {}) or {}
    expiration = creds.get("Expiration")
    return AssumeAttempt(
        role_arn=arn,
        status="success",
        assumed_arn=str(assumed.get("Arn") or ""),
        session_expiration=(expiration.isoformat() if hasattr(expiration, "isoformat") else str(expiration or "")),
    )


def _classify_client_error(code: str, message: str) -> str:
    """Map an AWS error code to one of our high-level statuses.

    Both "caller lacks ``sts:AssumeRole``" and "role trust policy
    disallows this principal" surface as ``AccessDenied`` — the only
    signal that distinguishes them is the message text, so we inspect
    that before falling back to the generic code mapping.
    """
    code = code or ""
    lowered = message.lower()

    if code in {"NoSuchEntity", "NoSuchEntityException"}:
        return "no_such_role"
    if code in {"MalformedPolicyDocument", "ValidationError", "InvalidParameterValue"}:
        return "malformed"
    if code in {"Throttling", "ThrottlingException", "RequestLimitExceeded"}:
        return "throttled"
    if code in {"AccessDenied", "AccessDeniedException"}:
        if "trust" in lowered and "policy" in lowered:
            return "trust_denied"
        return "access_denied"
    return "error"


def _attempt_to_row(attempt: AssumeAttempt) -> dict[str, Any]:
    return {
        "kind": "assume_attempt",
        "role_arn": attempt.role_arn,
        "status": attempt.status,
        "assumed_arn": attempt.assumed_arn,
        "session_expiration": attempt.session_expiration,
        "error_code": attempt.error_code,
        "error_message": attempt.error_message,
    }


def _summarise(attempts: list[AssumeAttempt]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for a in attempts:
        counts[a.status] = counts.get(a.status, 0) + 1
    return {
        "attempts_total": len(attempts),
        "status_counts": counts,
        "success_arns": [a.role_arn for a in attempts if a.status == "success"],
    }


def _render_verdict(console: Console, attempts: list[AssumeAttempt]) -> None:
    """Print a concise, colour-coded one-line summary per status bucket."""
    if not attempts:
        return
    buckets: dict[str, int] = {}
    for a in attempts:
        buckets[a.status] = buckets.get(a.status, 0) + 1
    console.print()
    console.rule("[muted]verdict[/muted]", style="muted")
    for status, count in sorted(buckets.items(), key=lambda kv: -kv[1]):
        style = _STATUS_STYLES.get(status, "muted")
        console.print(f"  [{style}]{status}[/{style}]: {count}")
    successes = [a for a in attempts if a.status == "success"]
    if successes:
        console.print()
        console.print("[success]assumable now:[/success]")
        for a in successes:
            console.print(f"  - {a.assumed_arn or a.role_arn}")
