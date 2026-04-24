"""CodeCommit — repositories, triggers, pull requests.

Repository triggers often wire SNS / Lambda endpoints that execute with
elevated roles on push events — worth flagging for an auditor.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.aws.base import AwsService, ServiceContext, safe
from cloud_service_enum.core.models import ServiceResult

_BATCH = 25
_OPEN_PR_CAP = 25


class CodeCommitService(AwsService):
    service_name = "codecommit"
    is_regional = True

    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        focused = ctx.is_focused_on(self.service_name)
        async with ctx.client("codecommit") as cc:
            repo_summaries = await _list_repositories(cc)
            repo_names = [
                r.get("repositoryName") for r in repo_summaries if r.get("repositoryName")
            ]
            repos = await _batch_get(cc, repo_names)
            for repo in repos:
                row = await _repo_row(cc, repo, ctx.region, focused)
                result.resources.append(row)

        result.cis_fields.setdefault("per_region", {})[ctx.region] = {
            "repository_count": len(repos),
        }


async def _list_repositories(cc: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = await safe(cc.list_repositories(**kwargs))
        if not resp:
            break
        items.extend(resp.get("repositories", []) or [])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


async def _batch_get(cc: Any, names: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for start in range(0, len(names), _BATCH):
        chunk = names[start : start + _BATCH]
        resp = await safe(cc.batch_get_repositories(repositoryNames=chunk))
        out.extend((resp or {}).get("repositories", []) or [])
    return out


async def _repo_row(
    cc: Any, repo: dict[str, Any], region: str, focused: bool
) -> dict[str, Any]:
    name = repo.get("repositoryName")
    row: dict[str, Any] = {
        "kind": "codecommit-repo",
        "id": repo.get("Arn") or name,
        "arn": repo.get("Arn"),
        "name": name,
        "region": region,
        "description": repo.get("repositoryDescription"),
        "default_branch": repo.get("defaultBranch"),
        "clone_url_http": repo.get("cloneUrlHttp"),
        "clone_url_ssh": repo.get("cloneUrlSsh"),
        "account_id": repo.get("accountId"),
        "last_modified": repo.get("lastModifiedDate"),
    }
    if not name:
        return row
    triggers_resp = await safe(cc.get_repository_triggers(repositoryName=name))
    triggers = (triggers_resp or {}).get("triggers", []) or []
    if triggers:
        row["triggers"] = [
            {
                "name": t.get("name"),
                "destination": t.get("destinationArn"),
                "events": t.get("events") or [],
                "branches": t.get("branches") or [],
                "custom_data": t.get("customData"),
            }
            for t in triggers
        ]
    if focused:
        pr_ids = await _list_open_prs(cc, name)
        if pr_ids:
            row["open_pull_request_count"] = len(pr_ids)
            row["open_pull_requests"] = pr_ids[:_OPEN_PR_CAP]
    return row


async def _list_open_prs(cc: Any, repo_name: str) -> list[str]:
    ids: list[str] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {
            "repositoryName": repo_name,
            "pullRequestStatus": "OPEN",
        }
        if next_token:
            kwargs["nextToken"] = next_token
        resp = await safe(cc.list_pull_requests(**kwargs))
        if not resp:
            break
        ids.extend(resp.get("pullRequestIds", []) or [])
        next_token = resp.get("nextToken")
        if not next_token or len(ids) >= _OPEN_PR_CAP:
            break
    return ids
