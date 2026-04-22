"""Bundled data files (permission catalogues, wordlists)."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def data_path(name: str) -> Path:
    """Return absolute filesystem path to a bundled data file."""
    return Path(str(files(__package__).joinpath(name)))


def load_lines(name: str) -> list[str]:
    """Load a newline-delimited bundled file, skipping blanks/comments."""
    text = data_path(name).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
