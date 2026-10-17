from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DBGW_")

    metadata_db_path: Path = Path("./var/metadata.sqlite3")
    openfga_api_url: str = "http://localhost:58080"
    openfga_store_id: str | None = None
    openfga_model_id: str | None = None
    sync_poll_interval_s: float = 2.0
    reconcile_interval_s: float = 600.0
    revoke_sync_timeout_s: float = 5.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
