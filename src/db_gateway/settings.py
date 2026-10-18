from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DBGW_")

    metadata_db_path: Path = Path("./var/metadata.sqlite3")
    openfga_api_url: str = "http://localhost:58080"
    openfga_store_id: str | None = None
    openfga_model_id: str | None = None
    sync_poll_interval_s: float = Field(default=2.0, gt=0)
    reconcile_interval_s: float = Field(default=600.0, gt=0)
    revoke_sync_timeout_s: float = Field(default=5.0, ge=0)
    target_connect_timeout_s: int = Field(default=5, gt=0)


@lru_cache
def get_settings() -> Settings:
    return Settings()
