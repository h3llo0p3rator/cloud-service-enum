"""GCP sub-command group: ``cse gcp enumerate``."""

from __future__ import annotations

import click

from cloud_service_enum.clis.common import (
    deep_scan_options,
    emit_reports,
    report_options,
    resolve_deep_flags,
    run_async,
)
from cloud_service_enum.core.models import Provider, Scope
from cloud_service_enum.core.registry import registry
from cloud_service_enum.core.runner import run_provider


@click.group(help="Enumerate Google Cloud Platform resources across projects.")
def gcp() -> None:  # noqa: D401
    pass


def _auth_options(fn):  # type: ignore[no-untyped-def]
    fn = click.option("--service-account-file", type=click.Path(dir_okay=False, exists=True))(fn)
    fn = click.option("--service-account-json", help="Raw SA JSON (prefer the file flag).")(fn)
    fn = click.option("--access-token", help="Pre-minted OAuth2 access token.")(fn)
    fn = click.option("--impersonate", "impersonate_service_account", help="SA email to impersonate.")(fn)
    fn = click.option("--workload-identity-config", type=click.Path(dir_okay=False), help="WIF config JSON.")(fn)
    fn = click.option("--quota-project", help="Override quota project.")(fn)
    fn = click.option("--project", "project_id", help="Project id (single-project mode).")(fn)
    return fn


@gcp.command("enumerate", help="Run a full or scoped GCP enumeration.")
@_auth_options
@click.option("--projects", "projects", multiple=True, help="Project id(s) to scan (repeat or comma-sep).")
@click.option("--service", "services", multiple=True, help="Restrict to given service(s).")
@click.option("--max-concurrency", type=int, default=10, show_default=True)
@click.option("--timeout", "timeout_s", type=float, default=180.0, show_default=True)
@click.option("--no-progress", is_flag=True)
@deep_scan_options
@report_options
def gcp_enumerate(
    service_account_file: str | None,
    service_account_json: str | None,
    access_token: str | None,
    impersonate_service_account: str | None,
    workload_identity_config: str | None,
    quota_project: str | None,
    project_id: str | None,
    projects: tuple[str, ...],
    services: tuple[str, ...],
    max_concurrency: int,
    timeout_s: float,
    no_progress: bool,
    deep_scan: bool | None,
    secret_scan: bool | None,
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    from cloud_service_enum import gcp as gcp_pkg  # noqa: F401 - register services
    from cloud_service_enum.gcp.auth import GcpAuthConfig, GcpAuthenticator

    cfg = GcpAuthConfig(
        service_account_file=service_account_file,
        service_account_json=service_account_json,
        access_token=access_token,
        impersonate_service_account=impersonate_service_account,
        workload_identity_config=workload_identity_config,
        quota_project=quota_project,
        project_id=project_id,
    )
    auth = GcpAuthenticator(cfg)
    service_list = _split(services)
    effective_deep, effective_secret = resolve_deep_flags(
        services=service_list,
        deep_scan=deep_scan,
        secret_scan=secret_scan,
    )
    scope = Scope(
        provider=Provider.GCP,
        project_ids=_split(projects) or ([project_id] if project_id else []),
        services=service_list,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        deep_scan=effective_deep,
        secret_scan=effective_secret,
    )
    run = run_async(run_provider(Provider.GCP, auth, scope, show_progress=not no_progress))
    emit_reports(run, output_dir, report_formats)


@gcp.command("services", help="List the GCP services the tool can enumerate.")
def gcp_services() -> None:
    from cloud_service_enum import gcp as gcp_pkg  # noqa: F401

    for name in registry.names(Provider.GCP):
        click.echo(name)


def _split(values: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for v in values:
        out.extend(part.strip() for part in v.split(",") if part.strip())
    return out
