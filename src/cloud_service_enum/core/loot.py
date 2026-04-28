"""Helpers for writing downloaded cloud objects into ``loot/``."""

from __future__ import annotations

from pathlib import Path


def loot_destination(*, owner: str, key: str, root: Path | None = None) -> Path:
    """Build a collision-safe destination path under ``loot/<owner>/...``."""
    base = (root or Path("loot")) / _safe_segment(owner)
    clean_key = key.strip().lstrip("/")
    parts = [_safe_segment(part) for part in clean_key.split("/") if part.strip()]
    if not parts:
        parts = ["unnamed-object"]
    candidate = base.joinpath(*parts)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    if not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    for idx in range(1, 1000):
        alt = candidate.with_name(f"{stem}-{idx}{suffix}")
        if not alt.exists():
            return alt
    return candidate.with_name(f"{stem}-{candidate.stat().st_mtime_ns}{suffix}")


def _safe_segment(value: str) -> str:
    cleaned = value.strip().replace("\\", "/")
    cleaned = cleaned.replace("..", "").replace(":", "_")
    cleaned = cleaned.strip("/").strip()
    return cleaned or "unnamed"
