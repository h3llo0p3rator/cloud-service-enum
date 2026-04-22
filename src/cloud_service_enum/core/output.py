"""Lean Rich-based console and progress helpers.

The previous codebase layered several formatter modules on top of Rich;
this module exposes only the two things every caller needs: a singleton
:class:`~rich.console.Console` and a ``progress_bar`` context manager.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from rich.console import Console as _RichConsole
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.theme import Theme

Console = _RichConsole

_THEME = Theme(
    {
        "info": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "bold red",
        "muted": "grey58",
    }
)

_console: Console | None = None


def get_console() -> Console:
    global _console
    if _console is None:
        _console = Console(theme=_THEME, highlight=False)
    return _console


@contextmanager
def progress_bar(*, transient: bool = False) -> Any:
    """Yield a configured :class:`Progress` with consistent columns."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=get_console(),
        transient=transient,
    ) as progress:
        yield progress
