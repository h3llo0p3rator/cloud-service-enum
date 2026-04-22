"""Runtime configuration loaded from environment variables.

Values here are infrastructure-level knobs (concurrency, timeouts,
output directory). Per-run scope lives in
:class:`cloud_service_enum.core.models.Scope`.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CSE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    max_concurrency: int = Field(default=10, ge=1, le=200)
    timeout_s: float = Field(default=120.0, ge=1.0)
    output_dir: Path = Field(default=Path("output"))
    http_timeout_s: float = Field(default=30.0, ge=1.0)
    log_level: str = "INFO"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
