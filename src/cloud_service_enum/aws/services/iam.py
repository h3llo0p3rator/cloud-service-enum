"""IAM enumeration — users, roles, groups, policies, account summary."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cloud_service_enum.aws.base import (
    AwsService,
    ServiceContext,
    collect_items,
    paginate,
    safe,
)
from cloud_service_enum.core.models import ServiceResult

# STS actions whose presence in an attached policy tells an auditor what
# the caller is allowed to assume. We also look for wildcards (``sts:*``
# / ``*``) so over-broad grants surface as assumable-role hits.
_ASSUME_ACTIONS: frozenset[str] = frozenset(
    {
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
        "sts:TagSession",
        "sts:SetSourceIdentity",
    }
)


class IamService(AwsService):
    service_name = "iam"
    is_regional = False

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("sts") as sts:
            caller = await safe(sts.get_caller_identity())
        async with ctx.client("iam") as iam:
            # Caller introspection is done first and attached immediately
            # so a scoped role with no iam:List* still surfaces "here's
            # who you are and what you can assume" even when the broader
            # listing calls below blow up with AccessDenied.
            caller_rows = await _caller_introspection(iam, caller)
            result.resources.extend(caller_rows)

            users = await _try_list(self._users, iam)
            roles = await _try_list(self._roles, iam)
            groups = await _try_list(self._groups, iam)
            policies = await _try_policies(self._managed_policies, iam, ctx.scope.iam_policy_bodies)
            summary = (await safe(iam.get_account_summary())) or {}
            password_policy = (await safe(iam.get_account_password_policy())) or {}

        result.resources.extend(users + roles + groups + policies)
        result.cis_fields = {
            "user_count": len(users),
            "role_count": len(roles),
            "group_count": len(groups),
            "managed_policy_count": len(policies),
            "users_with_mfa": sum(1 for u in users if u.get("mfa_enabled")),
            "users_with_console": sum(1 for u in users if u.get("console_enabled")),
            "stale_access_keys": sum(
                1 for u in users for k in u.get("access_keys", []) if k.get("stale")
            ),
            "assumable_roles": sum(1 for r in caller_rows if r["kind"] == "assumable_role"),
            "account_summary": summary.get("SummaryMap", {}),
            "password_policy": password_policy.get("PasswordPolicy"),
        }

    async def _users(self, iam: Any) -> list[dict[str, Any]]:
        pages = await paginate(iam, "list_users")
        users = collect_items(pages, "Users")
        out: list[dict[str, Any]] = []
        for u in users:
            name = u["UserName"]
            mfa = await safe(iam.list_mfa_devices(UserName=name))
            keys = await safe(iam.list_access_keys(UserName=name))
            login = await safe(iam.get_login_profile(UserName=name))
            out.append(
                {
                    "kind": "user",
                    "id": u["UserId"],
                    "arn": u["Arn"],
                    "name": name,
                    "created": u.get("CreateDate"),
                    "mfa_enabled": bool((mfa or {}).get("MFADevices")),
                    "console_enabled": login is not None,
                    "access_keys": [
                        {
                            "id": k["AccessKeyId"],
                            "status": k["Status"],
                            "created": k["CreateDate"],
                            "stale": _stale(k["CreateDate"]),
                        }
                        for k in (keys or {}).get("AccessKeyMetadata", [])
                    ],
                    "last_used": u.get("PasswordLastUsed"),
                }
            )
        return out

    async def _roles(self, iam: Any) -> list[dict[str, Any]]:
        pages = await paginate(iam, "list_roles")
        return [
            {
                "kind": "role",
                "id": r["RoleId"],
                "arn": r["Arn"],
                "name": r["RoleName"],
                "created": r.get("CreateDate"),
                "assume_role_policy": r.get("AssumeRolePolicyDocument"),
                "max_session_duration": r.get("MaxSessionDuration"),
            }
            for r in collect_items(pages, "Roles")
        ]

    async def _groups(self, iam: Any) -> list[dict[str, Any]]:
        pages = await paginate(iam, "list_groups")
        return [
            {
                "kind": "group",
                "id": g["GroupId"],
                "arn": g["Arn"],
                "name": g["GroupName"],
                "created": g.get("CreateDate"),
            }
            for g in collect_items(pages, "Groups")
        ]

    async def _managed_policies(
        self, iam: Any, include_bodies: bool
    ) -> list[dict[str, Any]]:
        pages = await paginate(iam, "list_policies", Scope="Local")
        out: list[dict[str, Any]] = []
        for p in collect_items(pages, "Policies"):
            row: dict[str, Any] = {
                "kind": "policy",
                "id": p["PolicyId"],
                "arn": p["Arn"],
                "name": p["PolicyName"],
                "attachment_count": p.get("AttachmentCount", 0),
                "is_attachable": p.get("IsAttachable", False),
            }
            if include_bodies and p.get("DefaultVersionId"):
                version = await safe(
                    iam.get_policy_version(
                        PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"]
                    )
                )
                doc = (version or {}).get("PolicyVersion", {}).get("Document")
                if doc:
                    row["policy_document"] = doc
            out.append(row)
        return out


async def _try_list(fn: Any, iam: Any) -> list[dict[str, Any]]:
    """Call a ``list_*`` enumerator, swallow AccessDenied / listing errors.

    Lets us run the caller-identity introspection on credentials that
    can do ``sts:GetCallerIdentity`` + ``iam:Get*`` on themselves, but
    lack account-wide ``iam:List*`` — without aborting the whole scan.
    """
    try:
        return await fn(iam)
    except Exception:  # noqa: BLE001
        return []


async def _try_policies(fn: Any, iam: Any, include_bodies: bool) -> list[dict[str, Any]]:
    """Same as :func:`_try_list` but for the 2-arg managed-policy fetcher."""
    try:
        return await fn(iam, include_bodies)
    except Exception:  # noqa: BLE001
        return []


def _stale(created: Any, threshold_days: int = 90) -> bool:
    try:
        return (datetime.now(timezone.utc) - created).days > threshold_days
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Caller-identity introspection
# ---------------------------------------------------------------------------


def _classify_caller(arn: str) -> tuple[str, str | None]:
    """Return ``(principal_type, principal_name)`` for an STS ARN.

    ``principal_name`` is the IAM user or role name usable with IAM APIs
    (i.e. with the session suffix stripped for ``assumed-role`` ARNs).
    Returns ``(principal_type, None)`` when no IAM-level name applies
    (root, federated-user, unknown shapes).
    """
    tail = arn.rsplit(":", 1)[-1] if ":" in arn else arn
    parts = tail.split("/")
    if parts[0] == "user" and len(parts) >= 2:
        return "user", parts[-1]
    if parts[0] == "role" and len(parts) >= 2:
        return "role", parts[-1]
    if parts[0] == "assumed-role" and len(parts) >= 2:
        return "assumed-role", parts[1]
    if parts[0] == "federated-user":
        return "federated-user", None
    if parts[0] == "root" or tail == "root":
        return "root", None
    return "unknown", None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statement_is_assume(stmt: dict[str, Any]) -> bool:
    """True when ``stmt`` grants one of :data:`_ASSUME_ACTIONS`."""
    actions = [str(a) for a in _as_list(stmt.get("Action"))]
    if not actions:
        return False
    for action in actions:
        if action in _ASSUME_ACTIONS:
            return True
        # Wildcard grants that cover sts:AssumeRole* — conservatively
        # match anything starting with ``sts:`` so the auditor sees it.
        if action == "*" or action.startswith("sts:"):
            return True
    return False


def _extract_assumable(
    policy_doc: Any, *, source: str, policy_name: str
) -> list[dict[str, Any]]:
    """Walk a policy document and yield one row per AssumeRole statement."""
    if not isinstance(policy_doc, dict):
        return []
    out: list[dict[str, Any]] = []
    statements = _as_list(policy_doc.get("Statement"))
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if (stmt.get("Effect") or "Allow") != "Allow":
            continue
        if not _statement_is_assume(stmt):
            continue
        resources = [str(r) for r in _as_list(stmt.get("Resource"))]
        actions = [str(a) for a in _as_list(stmt.get("Action"))]
        condition = stmt.get("Condition")
        condition_text = (
            json.dumps(condition, default=str) if isinstance(condition, (dict, list)) else ""
        )
        for resource in resources or ["(no Resource clause)"]:
            out.append(
                {
                    "kind": "assumable_role",
                    "resource": resource,
                    "actions": ", ".join(actions) or "(implicit)",
                    "via_policy": f"{source}:{policy_name}",
                    "condition": condition_text,
                }
            )
    return out


async def _policies_for_user(iam: Any, name: str) -> list[dict[str, Any]]:
    """Return caller_policy rows for an IAM user principal."""
    inline = await safe(iam.list_user_policies(UserName=name))
    attached = await safe(iam.list_attached_user_policies(UserName=name))
    rows: list[dict[str, Any]] = []
    for pol_name in (inline or {}).get("PolicyNames", []):
        body = await safe(iam.get_user_policy(UserName=name, PolicyName=pol_name))
        rows.append(
            {
                "kind": "caller_policy",
                "source": "inline",
                "name": pol_name,
                "arn": "",
                "policy_document": (body or {}).get("PolicyDocument"),
            }
        )
    for pol in (attached or {}).get("AttachedPolicies", []):
        rows.append(await _resolve_managed(iam, pol))
    return rows


async def _policies_for_role(iam: Any, name: str) -> list[dict[str, Any]]:
    """Return caller_policy rows for an IAM role principal."""
    inline = await safe(iam.list_role_policies(RoleName=name))
    attached = await safe(iam.list_attached_role_policies(RoleName=name))
    rows: list[dict[str, Any]] = []
    for pol_name in (inline or {}).get("PolicyNames", []):
        body = await safe(iam.get_role_policy(RoleName=name, PolicyName=pol_name))
        rows.append(
            {
                "kind": "caller_policy",
                "source": "inline",
                "name": pol_name,
                "arn": "",
                "policy_document": (body or {}).get("PolicyDocument"),
            }
        )
    for pol in (attached or {}).get("AttachedPolicies", []):
        rows.append(await _resolve_managed(iam, pol))
    return rows


async def _resolve_managed(iam: Any, pol: dict[str, Any]) -> dict[str, Any]:
    """Fetch the default version of a managed policy, best-effort."""
    arn = pol.get("PolicyArn", "")
    meta = await safe(iam.get_policy(PolicyArn=arn))
    default_version = (meta or {}).get("Policy", {}).get("DefaultVersionId")
    doc: Any = None
    if default_version:
        version = await safe(
            iam.get_policy_version(PolicyArn=arn, VersionId=default_version)
        )
        doc = (version or {}).get("PolicyVersion", {}).get("Document")
    return {
        "kind": "caller_policy",
        "source": "managed",
        "name": pol.get("PolicyName", arn),
        "arn": arn,
        "policy_document": doc,
    }


async def _caller_introspection(iam: Any, caller: Any) -> list[dict[str, Any]]:
    """Produce caller_identity + caller_policy + assumable_role rows.

    All IAM calls are wrapped in :func:`safe`, so when the principal
    lacks ``iam:List*`` / ``iam:Get*`` we still emit the identity row
    (driven purely by ``sts:GetCallerIdentity``) and just skip the policy
    dumps — matching the "fail gracefully" behaviour of the rest of the
    tool.
    """
    if not isinstance(caller, dict):
        return []

    arn = caller.get("Arn", "") or ""
    account = caller.get("Account", "") or ""
    user_id = caller.get("UserId", "") or ""
    principal_type, principal_name = _classify_caller(arn)

    policy_rows: list[dict[str, Any]] = []
    if principal_type == "user" and principal_name:
        policy_rows = await _policies_for_user(iam, principal_name)
    elif principal_type in {"role", "assumed-role"} and principal_name:
        policy_rows = await _policies_for_role(iam, principal_name)

    assumable_rows: list[dict[str, Any]] = []
    for row in policy_rows:
        assumable_rows.extend(
            _extract_assumable(
                row.get("policy_document"),
                source=row["source"],
                policy_name=row["name"],
            )
        )

    identity_row = {
        "kind": "caller_identity",
        "name": principal_name or user_id or "(unknown)",
        "arn": arn,
        "account": account,
        "principal_type": principal_type,
        "inline_policy_count": sum(1 for r in policy_rows if r["source"] == "inline"),
        "attached_policy_count": sum(1 for r in policy_rows if r["source"] == "managed"),
        "assumable_role_count": len(assumable_rows),
    }

    return [identity_row, *policy_rows, *assumable_rows]
