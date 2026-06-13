"""Runtime configuration, loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Optional VirusTotal API key. When unset, FileDessect still links to
    # the VirusTotal report for each file by hash but performs no live query.
    vt_api_key: str = ""

    # Directory where uploaded samples are stored for the duration of analysis.
    upload_dir: Path = Path("uploads")

    # Maximum accepted upload size, in megabytes.
    max_upload_mb: int = 100

    # Directory containing bundled YARA rules.
    rules_dir: Path = Path("rules")

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    return settings
