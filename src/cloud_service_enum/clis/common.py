"""Shared helpers for the CLI sub-commands (option sets, runners, etc.)."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, TypeVar

import click

from cloud_service_enum.core.errors import CloudServiceError
from cloud_service_enum.core.models import EnumerationRun
from cloud_service_enum.core.output import get_console
from cloud_service_enum.reporting import ReportFormat, write_reports

T = TypeVar("T")


def run_async(coro: Awaitable[T]) -> T:
    """Run an async command while surfacing errors cleanly to the CLI."""
    try:
        return asyncio.run(coro)  # type: ignore[arg-type]
    except CloudServiceError as exc:
        get_console().print(f"[error]{exc.__class__.__name__}:[/error] {exc}")
        raise click.exceptions.Exit(code=2) from exc
    except KeyboardInterrupt:
        get_console().print("[warn]interrupted[/warn]")
        raise click.exceptions.Exit(code=130) from None
    except Exception as exc:  # noqa: BLE001
        hint = _friendly_sdk_error(exc)
        if hint is None:
            raise
        get_console().print(f"[error]{hint}[/error]")
        raise click.exceptions.Exit(code=2) from exc


def _friendly_sdk_error(exc: BaseException) -> str | None:
    """Translate a handful of noisy SDK errors into a one-line message.

    Returns ``None`` when the exception should propagate (unexpected bug)
    rather than be swallowed.
    """
    name = exc.__class__.__name__
    if name == "NoRegionError":
        return (
            "AWS region is not set. Pass --region (e.g. --region us-east-1), "
            "configure one in your profile, or export AWS_DEFAULT_REGION."
        )
    if name in {"NoCredentialsError", "PartialCredentialsError"}:
        return f"AWS credentials missing or incomplete: {exc}"
    if name == "ProfileNotFound":
        return f"AWS profile not found: {exc}"
    if name == "EndpointConnectionError":
        return f"Could not reach AWS endpoint: {exc}"
    return None


def deep_scan_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Click decorator adding the shared ``--deep`` / ``--secret-scan`` flags.

    Both flags default to ``None`` so the caller can decide whether to
    auto-enable them based on whether the user restricted the run with
    ``--service``.
    """
    fn = click.option(
        "--secret-scan/--no-secret-scan",
        "secret_scan",
        default=None,
        help=(
            "Run regex credential detection on every text surface fetched during "
            "deep scans (env-var maps, startup scripts, workflow definitions). "
            "Opt-in; off in broad runs."
        ),
    )(fn)
    fn = click.option(
        "--deep/--no-deep",
        "deep_scan",
        default=None,
        help=(
            "Force deep-scan branches on every service. Defaults on when --service "
            "is restricted, off for a full enumeration."
        ),
    )(fn)
    return fn


def resolve_deep_flags(
    *,
    services: list[str],
    deep_scan: bool | None,
    secret_scan: bool | None,
) -> tuple[bool, bool]:
    """Apply the ``--deep`` / ``--secret-scan`` auto-enable logic.

    - ``deep_scan=True`` when the user passes it, otherwise when they
      restrict the run to one or more explicit ``--service`` values.
    - ``secret_scan`` is only auto-enabled along with ``deep_scan``; the
      user must still opt in explicitly for a full enumeration because
      it downloads / pattern-matches a lot of text.
    """
    focused = bool(services)
    effective_deep = deep_scan if deep_scan is not None else focused
    if secret_scan is not None:
        effective_secret = secret_scan
    else:
        effective_secret = effective_deep and focused
    return effective_deep, effective_secret


def report_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Click decorator adding ``--report-format`` and ``--output-dir``."""
    fn = click.option(
        "--report-format",
        "report_formats",
        type=click.Choice([f.value for f in ReportFormat], case_sensitive=False),
        multiple=True,
        default=("json",),
        show_default=True,
        help="Report format(s). Repeat to emit multiple.",
    )(fn)
    fn = click.option(
        "--output-dir",
        "output_dir",
        type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
        default=Path("./reports"),
        show_default=True,
        help="Directory where reports are written.",
    )(fn)
    return fn


def emit_reports(run: EnumerationRun, output_dir: Path, formats: tuple[str, ...]) -> None:
    """Write ``run`` to every format the user requested and print the paths."""
    console = get_console()
    parsed = [ReportFormat(f.lower()) for f in formats]
    paths = write_reports(run, output_dir, parsed)
    if not paths:
        return
    console.print()
    console.rule("[muted]reports[/muted]", style="muted")
    for p in paths:
        console.print(f"  [muted]wrote[/muted] {p}")
