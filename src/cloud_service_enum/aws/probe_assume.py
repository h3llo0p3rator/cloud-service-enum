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
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from rich.panel import Panel

from cloud_service_enum.aws.auth import AwsAuthConfig, AwsAuthenticator
from cloud_service_enum.core.display import render_service, render_summary
from cloud_service_enum.core.errors import AuthenticationError
from cloud_service_enum.core.models import EnumerationRun, Provider, Scope, ServiceResult
from cloud_service_enum.core.output import Console, get_console

# Arn shape: arn:aws:iam::<account>:role/<path>/<name>
_ROLE_ARN_RE = re.compile(
    r"^arn:(?P<partition>aws|aws-cn|aws-us-gov):iam::(?P<account>\d{12}):role(?:/.+)?$"
)
# Same shape but anchored for greedy extraction from free-form text.
_ROLE_ARN_SEARCH_RE = re.compile(
    r"arn:(?:aws|aws-cn|aws-us-gov):iam::\d{12}:role/[\w+=,.@\-/]+"
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
    # Per-ARN provenance ("via iam:caller_identity" / "via s3://…") carried
    # forward onto the attempt rows so reports say where each candidate
    # came from. Populated by :func:`arns_from_iam_scan` and the CLI.
    discovered_from: dict[str, str] = field(default_factory=dict)
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
    discovered_from: str = ""
    note: str = ""


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


def arns_from_iam_scan(source: Path) -> dict[str, str]:
    """Extract role ARN candidates from a ``cse aws enumerate`` JSON report.

    Walks ``run["services"][]["resources"][]`` and yields every candidate
    alongside a human-readable provenance string. Each candidate is
    emitted once (first-seen provenance wins) so the caller can merge
    the output with ``--target`` / ``--target-file`` ARNs without
    duplicating attempts.

    Sources we consider:

    * ``kind == "role"`` — the canonical role arn.
    * ``kind == "assumable_role"`` / ``"caller_policy"`` — surfaces left
      by the IAM caller introspection.
    * Free-form ARN strings matching the role pattern inside policy
      statements, resource arns, and other text bodies (``definition``,
      ``script``, ``startup_script``, ``user_data``, object excerpts,
      secret findings, generic string fields).
    """
    source = Path(source)
    if source.is_dir():
        candidates = sorted(
            source.glob("aws-*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            raise FileNotFoundError(f"no aws-*.json reports in {source}")
        source = candidates[0]
    try:
        raw = source.read_text(encoding="utf-8")
    except OSError as exc:  # noqa: BLE001
        raise FileNotFoundError(f"could not read {source}: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source} is not valid JSON: {exc}") from exc

    found: dict[str, str] = {}

    def _record(arn: str, provenance: str) -> None:
        if not arn or arn in found:
            return
        if not _ROLE_ARN_SEARCH_RE.fullmatch(arn):
            return
        found[arn] = provenance

    services = payload.get("services") or []
    for svc in services:
        service_name = svc.get("service") or "?"
        for row in svc.get("resources") or []:
            _extract_row(row, service_name, _record)

    return found


def _extract_row(
    row: dict[str, Any],
    service_name: str,
    record: Any,
) -> None:
    """Pull role ARNs out of a single resource row + its nested bodies."""
    kind = str(row.get("kind") or "")
    name = str(row.get("name") or row.get("id") or "")
    source_label = f"{service_name}:{kind}:{name}" if name else f"{service_name}:{kind}"

    if kind == "role":
        arn = row.get("arn") or row.get("id")
        if isinstance(arn, str):
            record(arn, f"iam:role {name or arn}")
    if kind in {"assumable_role", "caller_policy"}:
        resource = row.get("resource") or row.get("arn") or row.get("id")
        if isinstance(resource, str):
            record(resource, f"iam:{kind} via {name or resource}")

    # Walk policy documents and role-binding blocks for role ARNs in
    # Resource / principal statements. Every Statement.Resource may be
    # a string or a list of strings; both get coerced via the generic
    # text scan below.
    policy = row.get("policy_document") or row.get("assume_role_policy")
    if isinstance(policy, (dict, list)):
        for arn in _scan_json_for_role_arns(policy):
            record(arn, f"{source_label} · policy_document")

    for field_name in (
        "inline_policies",
        "attached_policies",
        "role_bindings",
    ):
        value = row.get(field_name)
        if isinstance(value, (dict, list)):
            for arn in _scan_json_for_role_arns(value):
                record(arn, f"{source_label} · {field_name}")

    for field_name in (
        "definition",
        "script",
        "startup_script",
        "user_data",
        "handler_excerpt",
    ):
        value = row.get(field_name)
        if isinstance(value, str):
            for arn in _ROLE_ARN_SEARCH_RE.findall(value):
                record(arn, f"{source_label} · {field_name}")

    # object / secret / free-form payloads — scan any nested string
    # bodies the service emitted.
    for arn in _scan_json_for_role_arns(row):
        record(arn, source_label)


def _scan_json_for_role_arns(value: Any) -> list[str]:
    """Walk a JSON-ish value collecting every role-ARN-shaped string."""
    out: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            out.extend(_ROLE_ARN_SEARCH_RE.findall(node))
            return
        if isinstance(node, dict):
            for sub in node.values():
                _walk(sub)
            return
        if isinstance(node, (list, tuple, set)):
            for sub in node:
                _walk(sub)

    _walk(value)
    return out


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
    caller_arn = str(identity.get("principal") or identity.get("arn") or "")
    is_root_caller = caller_arn.endswith(":root")

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

    if is_root_caller:
        _render_root_warning_panel(console)

    svc_started = datetime.now(timezone.utc)
    try:
        attempts = await _run_attempts(auth, scope)
    finally:
        await auth.close()

    if is_root_caller:
        for a in attempts:
            a.note = "root_caller"
    for a in attempts:
        if not a.discovered_from:
            a.discovered_from = scope.discovered_from.get(a.role_arn, "")

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
        "discovered_from": attempt.discovered_from or "",
        "note": attempt.note or "",
    }


def _render_root_warning_panel(console: Console) -> None:
    """Tell the user why every attempt is about to return ``access_denied``.

    STS categorically refuses ``AssumeRole`` from the account-root user
    regardless of the role's trust policy, so probing under root is a
    no-op. We still run the probes so the verdict block visibly confirms
    ``all access_denied``; every attempt is tagged ``note="root_caller"``
    so the JSON report explains itself.
    """
    body = (
        "The current identity is the [bold]account root user[/bold]. STS "
        "prohibits [code]sts:AssumeRole[/code] from root regardless of "
        "the role's trust policy.\n\n"
        "Every probe below will return [warning]access_denied[/warning] —"
        " this is a limitation of the caller, not of the target roles. "
        "Re-run under an IAM user or role that has [code]sts:AssumeRole"
        "[/code] for ground truth."
    )
    console.print(
        Panel(body, title="root caller detected", border_style="warning")
    )


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
