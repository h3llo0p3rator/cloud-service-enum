"""Azure sub-command group: ``cse azure enumerate`` and ``cse azure mfa``."""

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


@click.group(help="Enumerate Azure resources and Microsoft Graph identity data.")
def azure() -> None:  # noqa: D401
    pass


def _auth_options(fn):  # type: ignore[no-untyped-def]
    fn = click.option("--tenant-id", help="Azure AD tenant id.")(fn)
    fn = click.option("--client-id", help="Application/service principal client id.")(fn)
    fn = click.option("--client-secret", help="Service-principal secret.")(fn)
    fn = click.option("--certificate-path", type=click.Path(dir_okay=False), help="PEM certificate.")(fn)
    fn = click.option("--certificate-password", help="Password for the PFX/PEM cert, if any.")(fn)
    fn = click.option("--username", help="Username for user auth.")(fn)
    fn = click.option("--password", help="Password for user auth.")(fn)
    fn = click.option("--federated-token-file", type=click.Path(dir_okay=False, exists=True), help="Token file for WIF.")(fn)
    fn = click.option("--use-managed-identity", is_flag=True, help="Use the assigned managed identity.")(fn)
    fn = click.option("--use-cli", is_flag=True, help="Use `az login` credentials.")(fn)
    fn = click.option("--subscription", "subscription_id", help="Limit to a single subscription id.")(fn)
    return fn


def _build_auth(**kw):  # type: ignore[no-untyped-def]
    from cloud_service_enum import azure as azure_pkg  # noqa: F401 - register services
    from cloud_service_enum.azure.auth import AzureAuthConfig, AzureAuthenticator

    return AzureAuthenticator(AzureAuthConfig(**kw))


@azure.command("enumerate", help="Run a full or scoped Azure enumeration.")
@_auth_options
@click.option("--service", "services", multiple=True, help="Restrict to given service(s).")
@click.option("--max-concurrency", type=int, default=10, show_default=True)
@click.option("--timeout", "timeout_s", type=float, default=120.0, show_default=True)
@click.option("--no-progress", is_flag=True, help="Disable the Rich progress bar.")
@deep_scan_options
@report_options
def azure_enumerate(
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
    certificate_path: str | None,
    certificate_password: str | None,
    username: str | None,
    password: str | None,
    federated_token_file: str | None,
    use_managed_identity: bool,
    use_cli: bool,
    subscription_id: str | None,
    services: tuple[str, ...],
    max_concurrency: int,
    timeout_s: float,
    no_progress: bool,
    deep_scan: bool | None,
    secret_scan: bool | None,
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    auth = _build_auth(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        certificate_path=certificate_path,
        certificate_password=certificate_password,
        username=username,
        password=password,
        federated_token_file=federated_token_file,
        use_managed_identity=use_managed_identity,
        use_cli=use_cli,
        subscription_id=subscription_id,
    )
    service_list = list(services)
    effective_deep, effective_secret = resolve_deep_flags(
        services=service_list,
        deep_scan=deep_scan,
        secret_scan=secret_scan,
    )
    scope = Scope(
        provider=Provider.AZURE,
        subscription_ids=[subscription_id] if subscription_id else [],
        services=service_list,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        deep_scan=effective_deep,
        secret_scan=effective_secret,
    )
    run = run_async(run_provider(Provider.AZURE, auth, scope, show_progress=not no_progress))
    emit_reports(run, output_dir, report_formats)


@azure.command("mfa", help="Enumerate Microsoft Graph users and their MFA status.")
@_auth_options
@click.option("--no-progress", is_flag=True)
@report_options
def azure_mfa(
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
    certificate_path: str | None,
    certificate_password: str | None,
    username: str | None,
    password: str | None,
    federated_token_file: str | None,
    use_managed_identity: bool,
    use_cli: bool,
    subscription_id: str | None,
    no_progress: bool,
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    auth = _build_auth(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        certificate_path=certificate_path,
        certificate_password=certificate_password,
        username=username,
        password=password,
        federated_token_file=federated_token_file,
        use_managed_identity=use_managed_identity,
        use_cli=use_cli,
        subscription_id=subscription_id,
    )
    scope = Scope(
        provider=Provider.AZURE,
        services=["graph"],
        max_concurrency=4,
    )
    run = run_async(run_provider(Provider.AZURE, auth, scope, show_progress=not no_progress))
    emit_reports(run, output_dir, report_formats)


@azure.command("services", help="List the Azure services the tool can enumerate.")
def azure_services() -> None:
    from cloud_service_enum import azure as azure_pkg  # noqa: F401

    for name in registry.names(Provider.AZURE):
        click.echo(name)
