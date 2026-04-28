"""GCP sub-command group: ``cse gcp enumerate`` and ``cse gcp unauth``."""

from __future__ import annotations

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
@click.option("--download/--no-download", default=False, show_default=True, help="Enable storage object download mode.")
@click.option("--download-all", is_flag=True, default=False, help="Download all objects from resolved bucket targets.")
@click.option("--bucket", "download_buckets", multiple=True, help="Bucket target for download mode (repeatable).")
@click.option("--file", "download_files", multiple=True, help="Specific object key to download (repeatable).")
@click.option("--files", "download_files_csv", multiple=True, help="Comma-separated object keys to download.")
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
    download: bool,
    download_all: bool,
    download_buckets: tuple[str, ...],
    download_files: tuple[str, ...],
    download_files_csv: tuple[str, ...],
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
    effective_download, effective_download_all, selected_files = normalize_download_selection(
        download=download,
        download_all=download_all,
        files=download_files,
        files_csv=download_files_csv,
    )
    if effective_download and service_list and "storage" not in service_list:
        raise click.UsageError(
            "Storage download flags require --service storage (or omit --service for full enumerate)."
        )
    scope = Scope(
        provider=Provider.GCP,
        project_ids=_split(projects) or ([project_id] if project_id else []),
        services=service_list,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        deep_scan=effective_deep,
        secret_scan=effective_secret,
        download=effective_download,
        download_all=effective_download_all,
        download_files=list(selected_files),
        download_buckets=list(split_csv(download_buckets)),
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


@gcp.group("unauth", help="Unauthenticated recon against GCP-backed surfaces.")
def gcp_unauth() -> None:  # noqa: D401
    pass


@gcp_unauth.command(
    "bucket",
    help="Probe GCS buckets for public metadata / listing / IAM (optional URL crawl + bruteforce).",
)
@click.option(
    "--url", "target_url", default=None,
    help="Crawl this URL and extract GCS bucket references.",
)
@click.option(
    "--bucket", "buckets", multiple=True,
    help="Probe this bucket directly (repeatable).",
)
@click.option(
    "--bruteforce", is_flag=True, default=False,
    help="Enable wordlist bucket-name enumeration.",
)
@click.option(
    "--bruteforce-prefix", "bruteforce_prefixes", multiple=True,
    help="Prefix combined with each suffix wordlist entry (repeatable).",
)
@click.option(
    "--bruteforce-wordlist",
    type=click.Path(dir_okay=False, exists=True, path_type=Path),
    default=None,
    help="Suffix wordlist; defaults to the bundled gcs-bucket-suffixes.txt.",
)
@click.option("--max-objects", type=int, default=100, show_default=True)
@click.option("--max-object-size-kb", type=int, default=500, show_default=True)
@click.option("--download/--no-download", default=False, show_default=True, help="Enable object download mode.")
@click.option("--download-all", is_flag=True, default=False, help="Download all objects from resolved public buckets.")
@click.option("--file", "download_files", multiple=True, help="Specific object key to download (repeatable).")
@click.option("--files", "download_files_csv", multiple=True, help="Comma-separated object keys to download.")
@unauth_crawler_options
@report_options
def gcp_unauth_bucket(
    target_url: str | None,
    buckets: tuple[str, ...],
    bruteforce: bool,
    bruteforce_prefixes: tuple[str, ...],
    bruteforce_wordlist: Path | None,
    max_objects: int,
    max_object_size_kb: int,
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
    if not target_url and not buckets and not bruteforce:
        raise click.UsageError(
            "Provide at least one of --url, --bucket, or --bruteforce."
        )
    if bruteforce and not bruteforce_prefixes:
        raise click.UsageError(
            "--bruteforce requires at least one --bruteforce-prefix."
        )
    effective_download, effective_download_all, selected_files = normalize_download_selection(
        download=download,
        download_all=download_all,
        files=download_files,
        files_csv=download_files_csv,
    )

    from cloud_service_enum.gcp.unauth import BucketUnauthScope, run_bucket_unauth

    scope = BucketUnauthScope(
        target_url=target_url,
        buckets=tuple(buckets),
        bruteforce=bruteforce,
        bruteforce_prefixes=tuple(bruteforce_prefixes),
        bruteforce_wordlist=bruteforce_wordlist,
        max_objects=max_objects,
        max_object_size_kb=max_object_size_kb,
        download=effective_download,
        download_all=effective_download_all,
        download_files=selected_files,
        max_pages=max_pages,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        user_agent=user_agent,
        extra_hosts=tuple(extra_hosts),
    )
    run = run_async(run_bucket_unauth(scope))
    emit_reports(run, output_dir, report_formats)


@gcp_unauth.command(
    "cloudrun",
    help="Extract *.run.app URLs + classify their auth posture (public vs IAM-gated).",
)
@click.option("--url", "target_url", default=None, help="Entry URL for the crawl.")
@click.option(
    "--run-url",
    "run_urls",
    multiple=True,
    help="Probe this Cloud Run URL directly (repeatable).",
)
@unauth_crawler_options
@report_options
def gcp_unauth_cloudrun(
    target_url: str | None,
    run_urls: tuple[str, ...],
    max_pages: int,
    max_concurrency: int,
    timeout_s: float,
    user_agent: str,
    extra_hosts: tuple[str, ...],
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    if not target_url and not run_urls:
        raise click.UsageError("Provide at least one of --url or --run-url.")

    from cloud_service_enum.gcp.unauth import (
        CloudRunUnauthScope,
        run_cloudrun_unauth,
    )

    scope = CloudRunUnauthScope(
        target_url=target_url,
        urls=tuple(run_urls),
        max_pages=max_pages,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        user_agent=user_agent,
        extra_hosts=tuple(extra_hosts),
    )
    run = run_async(run_cloudrun_unauth(scope))
    emit_reports(run, output_dir, report_formats)
