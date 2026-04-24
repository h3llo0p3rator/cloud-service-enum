"""Azure DevOps — projects, repos, pipelines, service connections, variable groups.

The DevOps REST API has no async SDK worth shipping, so we talk to it
over raw ``httpx`` with either a Personal Access Token (``--devops-pat``,
basic auth with empty username) or a bearer token scoped to the DevOps
app id (``499b84ac-1321-427f-aa17-267ca6975798/.default``) — pick the
latter via ``--bearer-token --bearer-resource devops``.

We never fetch secret *values*: service-connection authorisation and
variable-group secrets are hidden server-side. We only surface whether
a variable is marked ``isSecret`` and the shape of the connection.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService
from cloud_service_enum.core.models import ServiceResult

_API_VERSION = "7.1"
_DEVOPS_SCOPE = "499b84ac-1321-427f-aa17-267ca6975798/.default"


class DevOpsService(AzureService):
    service_name = "devops"
    tenant_scoped = True

    async def collect_tenant(
        self, auth: AzureAuthenticator, result: ServiceResult
    ) -> None:
        scope = self.scope
        org = getattr(scope, "devops_org", None) if scope else None
        pat = getattr(scope, "devops_pat", None) if scope else None
        if not org:
            result.errors.append(
                "devops: --devops-org is required; skipping"
            )
            return

        headers = await _build_headers(auth, pat)
        if not headers:
            result.errors.append(
                "devops: could not build auth headers "
                "(provide --devops-pat or a --bearer-token --bearer-resource devops)"
            )
            return

        base = f"https://dev.azure.com/{org}"
        async with httpx.AsyncClient(
            headers=headers, timeout=30.0, follow_redirects=True
        ) as client:
            projects = await _get_json(
                client, f"{base}/_apis/projects", params={"api-version": _API_VERSION}
            )
            if projects is None:
                result.errors.append(
                    f"devops: failed to list projects for org '{org}'"
                )
                return
            for project in projects.get("value", []) or []:
                await _collect_project(client, base, org, project, result)

        result.cis_fields = {
            "organization": org,
            "project_count": sum(
                1 for r in result.resources if r.get("kind") == "devops-project"
            ),
        }


async def _build_headers(
    auth: AzureAuthenticator, pat: str | None
) -> dict[str, str] | None:
    if pat:
        token = base64.b64encode(f":{pat}".encode()).decode()
        return {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
        }
    cred = auth.credential()
    try:
        access = await cred.get_token(_DEVOPS_SCOPE)
    except Exception:  # noqa: BLE001
        return None
    return {
        "Authorization": f"Bearer {access.token}",
        "Accept": "application/json",
    }


async def _get_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    try:
        resp = await client.get(url, params=params)
    except httpx.HTTPError:
        return None
    if resp.status_code >= 400:
        return None
    # DevOps returns HTML when a project is missing / auth is wrong;
    # guard against that.
    ct = resp.headers.get("content-type", "")
    if "json" not in ct:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


async def _collect_project(
    client: httpx.AsyncClient,
    base: str,
    org: str,
    project: dict[str, Any],
    result: ServiceResult,
) -> None:
    name = project.get("name")
    project_id = project.get("id")
    if not name:
        return
    result.resources.append(
        {
            "kind": "devops-project",
            "id": project_id,
            "name": name,
            "organization": org,
            "visibility": project.get("visibility"),
            "state": project.get("state"),
            "last_update": project.get("lastUpdateTime"),
            "description": project.get("description"),
        }
    )
    await _collect_repos(client, base, org, name, result)
    await _collect_build_definitions(client, base, org, name, result)
    await _collect_pipelines(client, base, org, name, result)
    await _collect_service_connections(client, base, org, name, result)
    await _collect_variable_groups(client, base, org, name, result)


async def _collect_repos(
    client: httpx.AsyncClient,
    base: str,
    org: str,
    project: str,
    result: ServiceResult,
) -> None:
    data = await _get_json(
        client,
        f"{base}/{project}/_apis/git/repositories",
        params={"api-version": _API_VERSION},
    )
    for repo in (data or {}).get("value", []) or []:
        result.resources.append(
            {
                "kind": "devops-repo",
                "id": repo.get("id"),
                "name": repo.get("name"),
                "organization": org,
                "project": project,
                "default_branch": repo.get("defaultBranch"),
                "web_url": repo.get("webUrl"),
                "ssh_url": repo.get("sshUrl"),
                "is_disabled": repo.get("isDisabled"),
                "size_bytes": repo.get("size"),
            }
        )


async def _collect_build_definitions(
    client: httpx.AsyncClient,
    base: str,
    org: str,
    project: str,
    result: ServiceResult,
) -> None:
    data = await _get_json(
        client,
        f"{base}/{project}/_apis/build/definitions",
        params={
            "api-version": _API_VERSION,
            "queryOrder": "lastModifiedDescending",
            "$top": 50,
            "includeAllProperties": "true",
        },
    )
    for definition in (data or {}).get("value", []) or []:
        repository = definition.get("repository") or {}
        variables = _summarise_variables(definition.get("variables") or {})
        result.resources.append(
            {
                "kind": "devops-pipeline",
                "id": definition.get("id"),
                "name": definition.get("name"),
                "organization": org,
                "project": project,
                "path": definition.get("path"),
                "process_type": (definition.get("process") or {}).get("type"),
                "repository": {
                    "id": repository.get("id"),
                    "name": repository.get("name"),
                    "type": repository.get("type"),
                    "default_branch": repository.get("defaultBranch"),
                    "url": repository.get("url"),
                },
                "queue_status": definition.get("queueStatus"),
                "variables": variables,
                "variable_count": len(variables),
                "secret_variable_count": sum(
                    1 for v in variables if v.get("is_secret")
                ),
                "authored_by": (
                    (definition.get("authoredBy") or {}).get("uniqueName")
                ),
                "created": definition.get("createdDate"),
            }
        )


async def _collect_pipelines(
    client: httpx.AsyncClient,
    base: str,
    org: str,
    project: str,
    result: ServiceResult,
) -> None:
    data = await _get_json(
        client,
        f"{base}/{project}/_apis/pipelines",
        params={"api-version": _API_VERSION},
    )
    for pipeline in (data or {}).get("value", []) or []:
        result.resources.append(
            {
                "kind": "devops-pipeline-yaml",
                "id": pipeline.get("id"),
                "name": pipeline.get("name"),
                "organization": org,
                "project": project,
                "folder": pipeline.get("folder"),
                "configuration_type": (pipeline.get("configuration") or {}).get(
                    "type"
                ),
                "configuration_path": (pipeline.get("configuration") or {}).get(
                    "path"
                ),
                "configuration_repository": (
                    (pipeline.get("configuration") or {}).get("repository") or {}
                ).get("fullName"),
            }
        )


async def _collect_service_connections(
    client: httpx.AsyncClient,
    base: str,
    org: str,
    project: str,
    result: ServiceResult,
) -> None:
    data = await _get_json(
        client,
        f"{base}/{project}/_apis/serviceendpoint/endpoints",
        params={"api-version": _API_VERSION},
    )
    for endpoint in (data or {}).get("value", []) or []:
        authorization = endpoint.get("authorization") or {}
        result.resources.append(
            {
                "kind": "devops-service-connection",
                "id": endpoint.get("id"),
                "name": endpoint.get("name"),
                "organization": org,
                "project": project,
                "type": endpoint.get("type"),
                "url": endpoint.get("url"),
                "is_shared": endpoint.get("isShared"),
                "is_ready": endpoint.get("isReady"),
                "auth_scheme": authorization.get("scheme"),
                "creator": (endpoint.get("createdBy") or {}).get("uniqueName"),
                "owner": endpoint.get("owner"),
                "description": endpoint.get("description"),
            }
        )


async def _collect_variable_groups(
    client: httpx.AsyncClient,
    base: str,
    org: str,
    project: str,
    result: ServiceResult,
) -> None:
    data = await _get_json(
        client,
        f"{base}/{project}/_apis/distributedtask/variablegroups",
        params={"api-version": _API_VERSION},
    )
    for group in (data or {}).get("value", []) or []:
        variables = _summarise_variables(group.get("variables") or {})
        result.resources.append(
            {
                "kind": "devops-variable-group",
                "id": group.get("id"),
                "name": group.get("name"),
                "organization": org,
                "project": project,
                "description": group.get("description"),
                "type": group.get("type"),
                "variables": variables,
                "variable_count": len(variables),
                "secret_variable_count": sum(
                    1 for v in variables if v.get("is_secret")
                ),
                "modified_by": (group.get("modifiedBy") or {}).get("uniqueName"),
                "modified_on": group.get("modifiedOn"),
            }
        )


def _summarise_variables(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a DevOps ``variables`` map; hide values when ``isSecret``."""
    out: list[dict[str, Any]] = []
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        is_secret = bool(entry.get("isSecret"))
        out.append(
            {
                "name": key,
                "is_secret": is_secret,
                "value": None if is_secret else entry.get("value"),
                "allow_override": entry.get("allowOverride"),
            }
        )
    return out
