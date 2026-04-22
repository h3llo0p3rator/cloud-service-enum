"""OSINT sub-command: ``cse osint <domain>``."""

from __future__ import annotations

from pathlib import Path

import click

from cloud_service_enum.clis.common import emit_reports, report_options, run_async
from cloud_service_enum.osint import OsintScope, run_osint


@click.command(
    "osint",
    help="Discover subdomains, attribute IPs to cloud providers, and probe Azure tenant info.",
)
@click.argument("domain")
@click.option("--wordlist", type=click.Path(dir_okay=False, exists=True), help="Subdomain wordlist.")
@click.option("--max-concurrency", type=int, default=40, show_default=True)
@click.option("--timeout", "timeout_s", type=float, default=15.0, show_default=True)
@click.option("--skip-brute", is_flag=True, help="Skip the wordlist brute-force phase.")
@click.option("--no-ct", is_flag=True, help="Skip Certificate Transparency log queries.")
@click.option("--no-rdap", is_flag=True, help="Skip RDAP IP-ownership lookups.")
@click.option("--no-tenant", is_flag=True, help="Skip the Azure tenant-id probe.")
@click.option("--whois", "do_whois", is_flag=True, help="Include domain WHOIS in the JSON report.")
@click.option("--ssl-inspect", is_flag=True, help="Inspect leaf certificates on TCP/443 (slow).")
@click.option("--extra", "extras", multiple=True, help="Additional hostnames to force-include.")
@report_options
def osint(
    domain: str,
    wordlist: str | None,
    max_concurrency: int,
    timeout_s: float,
    skip_brute: bool,
    no_ct: bool,
    no_rdap: bool,
    no_tenant: bool,
    do_whois: bool,
    ssl_inspect: bool,
    extras: tuple[str, ...],
    output_dir: Path,
    report_formats: tuple[str, ...],
) -> None:
    words: list[str] = []
    if wordlist:
        words = [line.strip() for line in Path(wordlist).read_text().splitlines() if line.strip()]
    scope = OsintScope(
        domain=domain,
        wordlist=words,
        max_concurrency=max_concurrency,
        http_timeout_s=timeout_s,
        brute_force=not skip_brute,
        ct_logs=not no_ct,
        rdap=not no_rdap,
        azure_tenant=not no_tenant,
        whois=do_whois,
        ssl_inspect=ssl_inspect,
        extra_hostnames=list(extras),
    )
    run = run_async(run_osint(scope))
    emit_reports(run, output_dir, report_formats)
