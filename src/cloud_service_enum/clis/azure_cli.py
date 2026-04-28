"""Azure sub-command group: ``cse azure enumerate``, ``mfa``, ``unauth``."""

from __future__ import annotations

import os
from pathlib import Path

import click

from cloud_service_enum.clis.common import (
    deep_scan_options,
    emit_reports,
    normalize_download_selection,
    report_options,
    resolve_deep_flags,
    run_async,
    split_csv,
    unauth_crawler_options,
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
    fn = click.option(
        "--bearer-token",
        "bearer_token",
        default=None,
        help=(
            "Replay a pre-issued OAuth bearer token (e.g. an exfiltrated "
            "managed-identity JWT). Takes precedence over every other "
            "auth flag."
        ),
    )(fn)
    fn = click.option(
        "--bearer-resource",
        "bearer_resource",
        type=click.Choice(["management", "graph", "vault", "devops", "arm"]),
        default="management",
        show_default=True,
        help="Resource the bearer token was issued for.",
    )(fn)
    fn = click.option(
        "--bearer-expires-on",
        "bearer_expires_on",
        type=int,
        default=None,
        help=(
            "Override the JWT 'exp' claim with a unix timestamp "
            "(only needed for opaque / non-JWT tokens)."
        ),
    )(fn)
    return fn


def _build_auth(**kw):  # type: ignore[no-untyped-def]
    from cloud_service_enum import azure as azure_pkg  # noqa: F401 - register services
    from cloud_service_enum.azure.auth import AzureAuthConfig, AzureAuthenticator

    return AzureAuthenticator(AzureAuthConfig(**kw))


@azure.command("enumerate", help="Run a full or scoped Azure enumeration.")
@_auth_options
@click.option("--service", "services", multiple=True, help="Restrict to given service(s).")
@click.option("--download/--no-download", default=False, show_default=True, help="Enable storage object download mode.")
@click.option("--download-all", is_flag=True, default=False, help="Download all objects from resolved storage targets.")
@click.option("--account", "download_accounts", multiple=True, help="Storage account target for download mode (repeatable).")
@click.option("--storage-account-key", "storage_account_key", default=None, help="Storage account key for authenticated storage download mode.")
@click.option("--container", "download_containers", multiple=True, help="Storage container target for download mode (repeatable).")
@click.option("--file", "download_files", multiple=True, help="Specific object key to download (repeatable).")
@click.option("--files", "download_files_csv", multiple=True, help="Comma-separated object keys to download.")
@click.option("--max-concurrency", type=int, default=10, show_default=True)
@click.option("--timeout", "timeout_s", type=float, default=120.0, show_default=True)
@click.option("--no-progress", is_flag=True, help="Disable the Rich progress bar.")
@click.option(
    "--devops-org",
    "devops_org",
    default=None,
    help=(
        "Azure DevOps organization name (required for the `devops` "
        "service; it will skip silently otherwise)."
    ),
)
@click.option(
    "--devops-pat",
    "devops_pat",
    default=None,
    help=(
        "Azure DevOps Personal Access Token. Takes precedence over "
        "--bearer-token when hitting dev.azure.com."
    ),
)
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
    bearer_token: str | None,
    bearer_resource: str,
    bearer_expires_on: int | None,
    services: tuple[str, ...],
    download: bool,
    download_all: bool,
    download_accounts: tuple[str, ...],
    storage_account_key: str | None,
    download_containers: tuple[str, ...],
    download_files: tuple[str, ...],
    download_files_csv: tuple[str, ...],
    max_concurrency: int,
    timeout_s: float,
    no_progress: bool,
    devops_org: str | None,
    devops_pat: str | None,
    deep_scan: bool | None,
    secret_scan: bool | None,
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    service_list = list(services)
    effective_deep, effective_secret = resolve_deep_flags(
        services=service_list,
        deep_scan=deep_scan,
        secret_scan=secret_scan,
    )
    effective_download, effective_download_all, selected_files = normalize_download_selection(
        download=download,
        download_all=download_all,
        files=download_files,
        files_csv=download_files_csv,
    )
    resolved_accounts = list(split_csv(download_accounts))
    env_account = (os.getenv("AZURE_STORAGE_ACCOUNT") or "").strip()
    env_key = (os.getenv("AZURE_STORAGE_KEY") or "").strip()
    resolved_storage_account = (
        resolved_accounts[0] if resolved_accounts else (env_account or None)
    )
    resolved_storage_key = storage_account_key or (env_key or None)
    storage_key_source = "cli" if storage_account_key else ("env" if env_key else None)
    if resolved_storage_key and len(resolved_accounts) > 1:
        raise click.UsageError(
            "Storage account key auth supports a single --account target."
        )
    if resolved_storage_key and not resolved_storage_account:
        raise click.UsageError(
            "Storage account key auth requires --account or AZURE_STORAGE_ACCOUNT."
        )
    if resolved_storage_key and service_list and "storage" not in service_list:
        raise click.UsageError(
            "Storage account key auth requires --service storage (or omit --service for full enumerate)."
        )
    if effective_download and service_list and "storage" not in service_list:
        raise click.UsageError(
            "Storage download flags require --service storage (or omit --service for full enumerate)."
        )
    if resolved_storage_account and not resolved_accounts:
        resolved_accounts = [resolved_storage_account]
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
        bearer_token=bearer_token,
        bearer_resource=bearer_resource,
        bearer_expires_on=bearer_expires_on,
        extra={
            "storage_account_name": resolved_storage_account,
            "storage_account_key": resolved_storage_key,
        },
    )
    scope = Scope(
        provider=Provider.AZURE,
        subscription_ids=[subscription_id] if subscription_id else [],
        services=service_list,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        deep_scan=effective_deep,
        secret_scan=effective_secret,
        devops_org=devops_org,
        devops_pat=devops_pat,
        download=effective_download,
        download_all=effective_download_all,
        download_files=list(selected_files),
        download_accounts=resolved_accounts,
        download_containers=list(split_csv(download_containers)),
        storage_account_name=resolved_storage_account,
        storage_account_key_source=storage_key_source,
    )
    run = run_async(run_provider(Provider.AZURE, auth, scope, show_progress=not no_progress))
    emit_reports(run, output_dir, report_formats)


@azure.command(
    "mfa",
    help=(
        "MFA tooling. Without an argument: enumerate every user's MFA "
        "registration status via Microsoft Graph. With a UPN: probe that "
        "user against multiple Microsoft auth endpoints to detect "
        "single-factor (MFA-bypass) access."
    ),
)
@click.argument("user", required=False)
@_auth_options
@click.option(
    "--mfa-password",
    "mfa_password",
    help="Password to test in the MFA sweep (interactive prompt if omitted).",
)
@click.option(
    "--mfa-tenant",
    "mfa_tenant",
    default=None,
    help="Tenant id/host for the sweep (default: organizations).",
)
@click.option(
    "--yes",
    "skip_confirm",
    is_flag=True,
    help="Skip the lockout confirmation prompt (non-interactive use).",
)
@click.option("--no-progress", is_flag=True)
@report_options
def azure_mfa(
    user: str | None,
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
    bearer_token: str | None,
    bearer_resource: str,
    bearer_expires_on: int | None,
    mfa_password: str | None,
    mfa_tenant: str | None,
    skip_confirm: bool,
    no_progress: bool,
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    if user:
        _run_mfa_sweep(
            upn=user,
            password=mfa_password,
            tenant=mfa_tenant or tenant_id or "organizations",
            skip_confirm=skip_confirm,
            output_dir=output_dir,
            report_formats=report_formats,
        )
        return

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
        bearer_token=bearer_token,
        bearer_resource=bearer_resource,
        bearer_expires_on=bearer_expires_on,
    )
    scope = Scope(
        provider=Provider.AZURE,
        services=["graph"],
        max_concurrency=4,
    )
    run = run_async(run_provider(Provider.AZURE, auth, scope, show_progress=not no_progress))
    emit_reports(run, output_dir, report_formats)


def _run_mfa_sweep(
    *,
    upn: str,
    password: str | None,
    tenant: str,
    skip_confirm: bool,
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    from cloud_service_enum.azure.mfa_sweep import MfaSweepScope, run_mfa_sweep

    click.secho(
        f"MFA sweep for user: {upn}",
        fg="cyan",
        bold=True,
    )
    click.secho(
        "This will issue several authentication requests against Microsoft "
        "endpoints. A wrong password may count toward the account lockout "
        "threshold.",
        fg="yellow",
    )
    if not skip_confirm and not click.confirm("Continue?", default=True):
        click.echo("Aborted.")
        return

    if not password:
        password = click.prompt(f"Password for {upn}", hide_input=True)

    scope = MfaSweepScope(upn=upn, password=password, tenant=tenant)
    run = run_async(run_mfa_sweep(scope))
    emit_reports(run, output_dir, report_formats)


@azure.command("services", help="List the Azure services the tool can enumerate.")
def azure_services() -> None:
    from cloud_service_enum import azure as azure_pkg  # noqa: F401

    for name in registry.names(Provider.AZURE):
        click.echo(name)


@azure.group("unauth", help="Unauthenticated recon against Azure-backed surfaces.")
def azure_unauth() -> None:  # noqa: D401
    pass


@azure_unauth.command(
    "storage",
    help="Probe Azure storage accounts + blob containers (optional URL crawl + bruteforce).",
)
@click.option(
    "--url", "target_url", default=None,
    help="Crawl this URL and extract storage-account / container references.",
)
@click.option(
    "--account", "accounts", multiple=True,
    help="Probe this storage account directly (repeatable).",
)
@click.option(
    "--container", "containers", multiple=True,
    help=(
        "Probe this container. Accepts ``<account>/<container>`` or a bare "
        "``<container>`` name (applied against every --account)."
    ),
)
@click.option(
    "--bruteforce", is_flag=True, default=False,
    help="Enable wordlist storage-account bruteforce.",
)
@click.option(
    "--bruteforce-prefix", "bruteforce_prefixes", multiple=True,
    help="Prefix combined with each suffix wordlist entry (repeatable).",
)
@click.option(
    "--bruteforce-wordlist",
    type=click.Path(dir_okay=False, exists=True, path_type=Path),
    default=None,
    help="Suffix wordlist; defaults to the bundled azure-storage-account-suffixes.txt.",
)
@click.option(
    "--bruteforce-container", is_flag=True, default=False,
    help="Use --container-wordlist instead of the built-in ~25 common container names.",
)
@click.option(
    "--container-wordlist",
    type=click.Path(dir_okay=False, exists=True, path_type=Path),
    default=None,
    help="Container wordlist (requires --bruteforce-container).",
)
@click.option("--max-blobs", type=int, default=100, show_default=True)
@click.option("--max-blob-size-kb", type=int, default=500, show_default=True)
@click.option("--download/--no-download", default=False, show_default=True, help="Enable blob download mode.")
@click.option("--download-all", is_flag=True, default=False, help="Download all blobs from resolved containers.")
@click.option("--file", "download_files", multiple=True, help="Specific blob key to download (repeatable).")
@click.option("--files", "download_files_csv", multiple=True, help="Comma-separated blob keys to download.")
@unauth_crawler_options
@report_options
def azure_unauth_storage(
    target_url: str | None,
    accounts: tuple[str, ...],
    containers: tuple[str, ...],
    bruteforce: bool,
    bruteforce_prefixes: tuple[str, ...],
    bruteforce_wordlist: Path | None,
    bruteforce_container: bool,
    container_wordlist: Path | None,
    max_blobs: int,
    max_blob_size_kb: int,
    download: bool,
    download_all: bool,
    download_files: tuple[str, ...],
    download_files_csv: tuple[str, ...],
    max_pages: int,
    max_concurrency: int,
    timeout_s: float,
    user_agent: str,
    extra_hosts: tuple[str, ...],
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    if not target_url and not accounts and not bruteforce:
        raise click.UsageError(
            "Provide at least one of --url, --account, or --bruteforce."
        )
    if bruteforce and not bruteforce_prefixes:
        raise click.UsageError(
            "--bruteforce requires at least one --bruteforce-prefix."
        )
    if bruteforce_container and not container_wordlist:
        raise click.UsageError(
            "--bruteforce-container requires --container-wordlist."
        )
    effective_download, effective_download_all, selected_files = normalize_download_selection(
        download=download,
        download_all=download_all,
        files=download_files,
        files_csv=download_files_csv,
    )

    from cloud_service_enum.azure.unauth import StorageUnauthScope, run_storage_unauth

    scope = StorageUnauthScope(
        target_url=target_url,
        accounts=tuple(accounts),
        containers=tuple(containers),
        bruteforce=bruteforce,
        bruteforce_prefixes=tuple(bruteforce_prefixes),
        bruteforce_wordlist=bruteforce_wordlist,
        bruteforce_container=bruteforce_container,
        container_wordlist=container_wordlist,
        max_blobs=max_blobs,
        max_blob_size_kb=max_blob_size_kb,
        download=effective_download,
        download_all=effective_download_all,
        download_files=selected_files,
        max_pages=max_pages,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        user_agent=user_agent,
        extra_hosts=tuple(extra_hosts),
    )
    run = run_async(run_storage_unauth(scope))
    emit_reports(run, output_dir, report_formats)


@azure_unauth.command(
    "appservice",
    help="Extract *.azurewebsites.net hostnames + probe canonical leak paths.",
)
@click.option("--url", "target_url", default=None, help="Entry URL for the crawl.")
@click.option(
    "--hostname",
    "hostnames",
    multiple=True,
    help="Probe this App Service hostname directly (repeatable).",
)
@unauth_crawler_options
@report_options
def azure_unauth_appservice(
    target_url: str | None,
    hostnames: tuple[str, ...],
    max_pages: int,
    max_concurrency: int,
    timeout_s: float,
    user_agent: str,
    extra_hosts: tuple[str, ...],
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    if not target_url and not hostnames:
        raise click.UsageError("Provide at least one of --url or --hostname.")

    from cloud_service_enum.azure.unauth import (
        AppServiceUnauthScope,
        run_appservice_unauth,
    )

    scope = AppServiceUnauthScope(
        target_url=target_url,
        hostnames=tuple(hostnames),
        max_pages=max_pages,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        user_agent=user_agent,
        extra_hosts=tuple(extra_hosts),
    )
    run = run_async(run_appservice_unauth(scope))
    emit_reports(run, output_dir, report_formats)
