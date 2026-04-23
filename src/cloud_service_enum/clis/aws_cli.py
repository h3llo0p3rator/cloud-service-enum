"""AWS sub-command group: ``cse aws enumerate`` and friends."""

from __future__ import annotations

from pathlib import Path

import click

from cloud_service_enum.clis.common import (
    deep_scan_options,
    emit_reports,
    report_options,
    resolve_deep_flags,
    run_async,
    unauth_crawler_options,
)
from cloud_service_enum.core.models import Provider, Scope
from cloud_service_enum.core.output import get_console
from cloud_service_enum.core.registry import registry
from cloud_service_enum.core.runner import run_provider


@click.group(help="Enumerate AWS resources across one or more regions.")
def aws() -> None:  # noqa: D401
    pass


def _auth_options(fn):  # type: ignore[no-untyped-def]
    fn = click.option("--profile", help="AWS profile name.")(fn)
    fn = click.option("--region", help="Initial region for session/STS.")(fn)
    fn = click.option("--access-key", help="Static access key id.")(fn)
    fn = click.option("--secret-key", help="Static secret access key.")(fn)
    fn = click.option("--session-token", help="Session token for temporary creds.")(fn)
    fn = click.option("--role-arn", help="Role to assume after initial auth.")(fn)
    fn = click.option("--external-id", help="External id for role assumption.")(fn)
    fn = click.option("--mfa-serial", help="MFA device serial/ARN.")(fn)
    fn = click.option("--mfa-token", help="MFA TOTP code to pass to AssumeRole.")(fn)
    fn = click.option(
        "--web-identity-token-file",
        type=click.Path(dir_okay=False, exists=True),
        help="Path to a web identity token file (WIF).",
    )(fn)
    return fn


@aws.command("enumerate", help="Run a full or scoped AWS enumeration.")
@_auth_options
@click.option("--regions", "regions", multiple=True, help="Region(s) to enumerate. Repeat or comma-sep.")
@click.option("--service", "services", multiple=True, help="Restrict to given service(s).")
@click.option("--max-concurrency", type=int, default=10, show_default=True)
@click.option("--timeout", "timeout_s", type=float, default=120.0, show_default=True)
@click.option("--no-progress", is_flag=True, help="Disable the Rich progress bar.")
@click.option(
    "--iam-policy-bodies/--no-iam-policy-bodies",
    default=True,
    show_default=True,
    help="Fetch JSON bodies for customer-managed IAM policies and render them.",
)
@click.option(
    "--s3-secret-scan/--no-s3-secret-scan",
    "s3_secret_scan",
    default=None,
    help=(
        "Legacy alias for --secret-scan restricted to S3 object bodies. "
        "Defaults on when --service is restricted to include s3; off otherwise."
    ),
)
@click.option(
    "--s3-scan-file-limit",
    type=int,
    default=100,
    show_default=True,
    help="Maximum objects scanned per bucket.",
)
@click.option(
    "--s3-scan-size-limit-kb",
    type=int,
    default=500,
    show_default=True,
    help="Maximum file size (KB) scanned per object.",
)
@deep_scan_options
@report_options
def aws_enumerate(
    profile: str | None,
    region: str | None,
    access_key: str | None,
    secret_key: str | None,
    session_token: str | None,
    role_arn: str | None,
    external_id: str | None,
    mfa_serial: str | None,
    mfa_token: str | None,
    web_identity_token_file: str | None,
    regions: tuple[str, ...],
    services: tuple[str, ...],
    max_concurrency: int,
    timeout_s: float,
    no_progress: bool,
    iam_policy_bodies: bool,
    s3_secret_scan: bool | None,
    s3_scan_file_limit: int,
    s3_scan_size_limit_kb: int,
    deep_scan: bool | None,
    secret_scan: bool | None,
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    from cloud_service_enum import aws as aws_pkg  # noqa: F401 - register services
    from cloud_service_enum.aws.auth import AwsAuthConfig, AwsAuthenticator

    cfg = AwsAuthConfig(
        profile=profile,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        role_arn=role_arn,
        external_id=external_id,
        mfa_serial=mfa_serial,
        mfa_token=mfa_token,
        web_identity_token_file=web_identity_token_file,
    )
    auth = AwsAuthenticator(cfg)

    async def _go():  # type: ignore[no-untyped-def]
        region_list = await _resolve_regions(auth, region, _split(regions))
        explicit_services = _split(services)
        effective_deep, effective_secret = resolve_deep_flags(
            services=explicit_services,
            deep_scan=deep_scan,
            secret_scan=secret_scan,
        )
        # Legacy --s3-secret-scan still takes precedence for S3 object scans
        # when set explicitly so existing invocations don't change meaning.
        if s3_secret_scan is None:
            s3_scan = effective_secret and (
                not explicit_services or "s3" in explicit_services
            )
        else:
            s3_scan = s3_secret_scan
        scope = Scope(
            provider=Provider.AWS,
            regions=region_list,
            services=explicit_services,
            max_concurrency=max_concurrency,
            timeout_s=timeout_s,
            deep_scan=effective_deep,
            secret_scan=effective_secret,
            iam_policy_bodies=iam_policy_bodies,
            s3_secret_scan=s3_scan,
            s3_scan_file_limit=s3_scan_file_limit,
            s3_scan_size_limit_kb=s3_scan_size_limit_kb,
        )
        return await run_provider(Provider.AWS, auth, scope, show_progress=not no_progress)

    run = run_async(_go())
    emit_reports(run, output_dir, report_formats)


@aws.command("services", help="List the AWS services the tool can enumerate.")
def aws_services() -> None:
    from cloud_service_enum import aws as aws_pkg  # noqa: F401

    for name in registry.names(Provider.AWS):
        click.echo(name)


@aws.command(
    "probe-assume",
    help=(
        "Actively probe sts:AssumeRole against candidate role ARNs. "
        "Ground truth for 'what can this token actually assume right now?'."
    ),
)
@_auth_options
@click.option(
    "--target",
    "probe_role_arns",
    multiple=True,
    help="Candidate role ARN to probe (repeatable or comma-separated).",
)
@click.option(
    "--target-file",
    "probe_role_arn_file",
    type=click.Path(dir_okay=False, exists=True, path_type=Path),
    default=None,
    help="File containing one candidate role ARN per line (# comments allowed).",
)
@click.option(
    "--target-external-id",
    "probe_external_id",
    default=None,
    help="External ID to pass to every probed AssumeRole call.",
)
@click.option(
    "--session-name",
    default="cse-probe-assume",
    show_default=True,
    help="Session name used for every successful AssumeRole.",
)
@click.option(
    "--duration-seconds",
    type=int,
    default=900,
    show_default=True,
    help="Requested session duration (900–3600; clamped to role's maximum).",
)
@click.option("--max-concurrency", type=int, default=10, show_default=True)
@click.option("--timeout", "timeout_s", type=float, default=30.0, show_default=True)
@report_options
def aws_probe_assume(
    profile: str | None,
    region: str | None,
    access_key: str | None,
    secret_key: str | None,
    session_token: str | None,
    role_arn: str | None,
    external_id: str | None,
    mfa_serial: str | None,
    mfa_token: str | None,
    web_identity_token_file: str | None,
    probe_role_arns: tuple[str, ...],
    probe_role_arn_file: Path | None,
    probe_external_id: str | None,
    session_name: str,
    duration_seconds: int,
    max_concurrency: int,
    timeout_s: float,
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    from cloud_service_enum.aws.probe_assume import (
        ProbeAssumeScope,
        load_role_arns,
        run_probe_assume,
    )

    arns = load_role_arns(probe_role_arns, path=probe_role_arn_file)
    if not arns:
        raise click.UsageError(
            "Provide at least one candidate via --target or --target-file."
        )

    scope = ProbeAssumeScope(
        role_arns=tuple(arns),
        external_id=probe_external_id,
        session_name=session_name,
        duration_seconds=duration_seconds,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        profile=profile,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        role_arn=role_arn,
        web_identity_token_file=web_identity_token_file,
    )
    _ = (external_id, mfa_serial, mfa_token)  # absorbed via shared option set
    run = run_async(run_probe_assume(scope))
    emit_reports(run, output_dir, report_formats)


@aws.group("unauth", help="Unauthenticated recon against public cloud-backed web apps.")
def aws_unauth() -> None:  # noqa: D401
    pass


@aws_unauth.command(
    "cognito",
    help="Crawl a web app for Cognito user pool / identity pool / app client IDs.",
)
@click.option("--url", "target_url", required=True, help="Entry URL for the crawl.")
@unauth_crawler_options
@click.option(
    "--probe/--no-probe",
    default=True,
    show_default=True,
    help="Run safe read-only Cognito probes (GetId, InitiateAuth) on every hit.",
)
@click.option(
    "--probe-signup",
    is_flag=True,
    default=False,
    help="Also probe SignUp to detect self-registration (no user is created).",
)
@report_options
def aws_unauth_cognito(
    target_url: str,
    max_pages: int,
    max_concurrency: int,
    timeout_s: float,
    user_agent: str,
    extra_hosts: tuple[str, ...],
    probe: bool,
    probe_signup: bool,
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    from cloud_service_enum.aws.unauth import CognitoUnauthScope, run_cognito_unauth

    scope = CognitoUnauthScope(
        target_url=target_url,
        max_pages=max_pages,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        user_agent=user_agent,
        extra_hosts=tuple(extra_hosts),
        probe=probe,
        probe_signup=probe_signup,
    )
    run = run_async(run_cognito_unauth(scope))
    emit_reports(run, output_dir, report_formats)


@aws_unauth.command(
    "s3",
    help="Probe S3 buckets for public access, optional bruteforce + object scan.",
)
@click.option(
    "--url", "target_url", default=None,
    help="Crawl this URL and extract bucket references.",
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
    help="Prefix(es) combined with each wordlist entry (repeatable).",
)
@click.option(
    "--bruteforce-wordlist",
    type=click.Path(dir_okay=False, exists=True, path_type=Path),
    default=None,
    help="Suffix wordlist; defaults to the bundled s3-bucket-suffixes.txt.",
)
@click.option("--max-objects", type=int, default=100, show_default=True)
@click.option("--max-object-size-kb", type=int, default=500, show_default=True)
@unauth_crawler_options
@report_options
def aws_unauth_s3(
    target_url: str | None,
    buckets: tuple[str, ...],
    bruteforce: bool,
    bruteforce_prefixes: tuple[str, ...],
    bruteforce_wordlist: Path | None,
    max_objects: int,
    max_object_size_kb: int,
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

    from cloud_service_enum.aws.unauth import S3UnauthScope, run_s3_unauth

    scope = S3UnauthScope(
        target_url=target_url,
        buckets=tuple(buckets),
        bruteforce=bruteforce,
        bruteforce_prefixes=tuple(bruteforce_prefixes),
        bruteforce_wordlist=bruteforce_wordlist,
        max_objects=max_objects,
        max_object_size_kb=max_object_size_kb,
        max_pages=max_pages,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        user_agent=user_agent,
        extra_hosts=tuple(extra_hosts),
    )
    run = run_async(run_s3_unauth(scope))
    emit_reports(run, output_dir, report_formats)


@aws_unauth.command(
    "api-gateway",
    help="Probe API Gateway endpoints and Lambda Function URLs.",
)
@click.option(
    "--url", "target_url", default=None,
    help="Crawl this URL and extract API Gateway / Lambda URL references.",
)
@click.option(
    "--api-url", "api_urls", multiple=True,
    help="Probe this API endpoint directly (repeatable).",
)
@unauth_crawler_options
@report_options
def aws_unauth_api_gateway(
    target_url: str | None,
    api_urls: tuple[str, ...],
    max_pages: int,
    max_concurrency: int,
    timeout_s: float,
    user_agent: str,
    extra_hosts: tuple[str, ...],
    output_dir,  # type: ignore[no-untyped-def]
    report_formats: tuple[str, ...],
) -> None:
    if not target_url and not api_urls:
        raise click.UsageError("Provide at least one of --url or --api-url.")

    from cloud_service_enum.aws.unauth import (
        ApiGatewayUnauthScope,
        run_api_gateway_unauth,
    )

    scope = ApiGatewayUnauthScope(
        target_url=target_url,
        api_urls=tuple(api_urls),
        max_pages=max_pages,
        max_concurrency=max_concurrency,
        timeout_s=timeout_s,
        user_agent=user_agent,
        extra_hosts=tuple(extra_hosts),
    )
    run = run_async(run_api_gateway_unauth(scope))
    emit_reports(run, output_dir, report_formats)


def _split(values: tuple[str, ...]) -> list[str]:
    items: list[str] = []
    for v in values:
        items.extend(part.strip() for part in v.split(",") if part.strip())
    return items


async def _resolve_regions(
    auth, single_region: str | None, explicit: list[str]
) -> list[str]:
    """Pick the region list to enumerate against without ever hard-failing.

    Priority order:

    1. ``--regions`` is honoured verbatim.
    2. ``--region`` falls through as a single-region scope (and avoids
       the ``ec2:DescribeRegions`` call entirely).
    3. Otherwise we try ``DescribeRegions`` and, if the principal lacks
       that permission, warn and fall back to :data:`FALLBACK_REGIONS`
       so global services (IAM, STS, Organizations, …) still run.
    """
    from cloud_service_enum.aws.auth import FALLBACK_REGIONS

    if explicit:
        return explicit
    if single_region:
        return [single_region]
    try:
        return await auth.list_regions()
    except Exception as exc:  # noqa: BLE001
        console = get_console()
        console.print(
            f"[warning]warning:[/warning] could not list regions via ec2:DescribeRegions "
            f"([muted]{type(exc).__name__}[/muted]); falling back to a canonical "
            f"{len(FALLBACK_REGIONS)}-region set. Pass [info]--regions[/info] to "
            f"override."
        )
        return list(FALLBACK_REGIONS)
