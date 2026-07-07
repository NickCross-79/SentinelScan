"""Application configuration (env-overridable)."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_DATA_DIR = Path.home() / ".sentinelscan"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    # Networking — local-first by default.
    host: str = "127.0.0.1"
    port: int = 8787
    # Origins allowed by CORS + the origin guard (SPA dev server, Tauri).
    allowed_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8787",
        "http://127.0.0.1:8787",
        "tauri://localhost",
    ]

    # Storage
    data_dir: Path = _DATA_DIR
    database_url: str = ""  # derived in model_post_init if empty

    # Auth (off by default for single-user local mode)
    auth_enabled: bool = False

    # Scan safety
    max_concurrent_scans: int = 2
    allow_public_targets: bool = False  # block non-private ranges unless overridden

    def model_post_init(self, __context) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.database_url:
            self.database_url = f"sqlite:///{self.data_dir / 'sentinelscan.db'}"

    @property
    def reports_dir(self) -> Path:
        d = self.data_dir / "reports"
        d.mkdir(parents=True, exist_ok=True)
        return d


settings = Settings()
