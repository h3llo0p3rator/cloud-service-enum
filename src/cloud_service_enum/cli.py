"""Click entry points for ``cse`` and ``cloud-service-enum``.

Each top-level command (``aws``, ``azure``, ``gcp``, ``osint``) lives in
its own module under ``cloud_service_enum.clis`` and is wired up here so
the main package imports remain light.
"""

from __future__ import annotations

import click

from cloud_service_enum.clis.aws_cli import aws
from cloud_service_enum.clis.azure_cli import azure
from cloud_service_enum.clis.gcp_cli import gcp
from cloud_service_enum.clis.osint_cli import osint


@click.group(
    help=(
        "Async multi-cloud enumeration for AWS, Azure, GCP, and OSINT targets. "
        "Use `cse <provider> enumerate` for a full scan, or a sub-command for a single service."
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(package_name="cloud-service-enum", prog_name="cse")
def main() -> None:  # noqa: D401
    """Top-level group; real work happens in sub-commands."""


main.add_command(aws)
main.add_command(azure)
main.add_command(gcp)
main.add_command(osint)


if __name__ == "__main__":
    main()
