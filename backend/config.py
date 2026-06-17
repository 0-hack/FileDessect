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

    # --- Interactive disassembly (opt-in) ------------------------------------
    # When enabled, an analysed native binary is retained in an isolated session
    # directory for `session_ttl_seconds` so the UI can drive the Rizin engine
    # on demand (disassemble/decompile any function — a live "Cutter in the
    # browser" experience). OFF by default: it means temporarily retaining
    # potentially-malicious samples, which the default privacy stance avoids.
    interactive_disasm: bool = False

    # How long a retained interactive session lives before it is purged.
    session_ttl_seconds: int = 1200

    # Samples larger than this are never retained for interactive sessions
    # (deep on-demand analysis would be too slow to be interactive).
    max_interactive_mb: int = 50

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def max_interactive_bytes(self) -> int:
        return self.max_interactive_mb * 1024 * 1024

    @property
    def session_dir(self) -> Path:
        return self.upload_dir / "sessions"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    return settings
