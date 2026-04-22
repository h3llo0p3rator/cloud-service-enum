"""IAM enumeration — users, roles, groups, policies, account summary."""

from __future__ import annotations

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


class IamService(AwsService):
    service_name = "iam"
    is_regional = False

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        async with ctx.client("iam") as iam:
            users = await self._users(iam)
            roles = await self._roles(iam)
            groups = await self._groups(iam)
            policies = await self._managed_policies(iam, ctx.scope.iam_policy_bodies)
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


def _stale(created: Any, threshold_days: int = 90) -> bool:
    try:
        return (datetime.now(timezone.utc) - created).days > threshold_days
    except Exception:  # noqa: BLE001
        return False
