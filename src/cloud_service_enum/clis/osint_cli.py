"""OSINT sub-command: ``cse osint <domain>``."""

from __future__ import annotations

from pathlib import Path

import click

from cloud_service_enum.clis.common import emit_reports, report_options, run_async
from cloud_service_enum.osint import OsintScope, run_osint


@click.command("osint", help="Discover subdomains, DNS records, and cloud-provider hints for a domain.")
@click.argument("domain")
@click.option("--wordlist", type=click.Path(dir_okay=False, exists=True), help="Subdomain wordlist.")
@click.option("--max-concurrency", type=int, default=40, show_default=True)
@click.option("--timeout", "timeout_s", type=float, default=10.0, show_default=True)
@click.option("--no-ct", is_flag=True, help="Skip certificate-transparency log query.")
@click.option("--no-whois", is_flag=True, help="Skip WHOIS lookup.")
@click.option("--ssl-inspect", is_flag=True, help="Inspect leaf certificates on TCP/443 (slow).")
@click.option("--extra", "extras", multiple=True, help="Additional hostnames to force-include.")
@report_options
def osint(
    domain: str,
    wordlist: str | None,
    max_concurrency: int,
    timeout_s: float,
    no_ct: bool,
    no_whois: bool,
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
        ct_logs=not no_ct,
        whois=not no_whois,
        ssl_inspect=ssl_inspect,
        extra_hostnames=list(extras),
    )
    run = run_async(run_osint(scope))
    emit_reports(run, output_dir, report_formats)
