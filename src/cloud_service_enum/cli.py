"""Click entry points for ``cse`` and ``cloud-service-enum``.

Each top-level command (``aws``, ``azure``, ``gcp``, ``osint``) lives in
its own module under ``cloud_service_enum.clis`` and is wired up here so
the main package imports remain light.
"""

from __future__ import annotations

import os

import click

from cloud_service_enum.clis.aws_cli import aws
from cloud_service_enum.clis.azure_cli import azure
from cloud_service_enum.clis.gcp_cli import gcp
from cloud_service_enum.clis.osint_cli import osint
from cloud_service_enum.core.output import configure_console


@click.group(
    help=(
        "Async multi-cloud enumeration for AWS, Azure, GCP, and OSINT targets. "
        "Use `cse <provider> enumerate` for a full scan, or a sub-command for a single service."
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--no-progress",
    is_flag=True,
    default=False,
    envvar="CSE_NO_PROGRESS",
    help="Suppress all Rich progress bars (env: CSE_NO_PROGRESS).",
)
@click.option(
    "--no-colour",
    "--no-color",
    "no_colour",
    is_flag=True,
    default=False,
    envvar=["CSE_NO_COLOUR", "CSE_NO_COLOR", "NO_COLOR"],
    help="Disable ANSI colour output (env: NO_COLOR / CSE_NO_COLOUR).",
)
@click.version_option(package_name="cloud-service-enum", prog_name="cse")
@click.pass_context
def main(ctx: click.Context, no_progress: bool, no_colour: bool) -> None:  # noqa: D401
    """Top-level group; real work happens in sub-commands."""
    # Respect the de-facto ``NO_COLOR`` standard even without the flag.
    if not no_colour and os.environ.get("NO_COLOR"):
        no_colour = True
    configure_console(no_color=no_colour, no_progress=no_progress)
    ctx.ensure_object(dict)
    ctx.obj["no_progress"] = no_progress
    ctx.obj["no_colour"] = no_colour


main.add_command(aws)
main.add_command(azure)
main.add_command(gcp)
main.add_command(osint)


if __name__ == "__main__":
    main()
