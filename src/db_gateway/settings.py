from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
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

    oidc_issuer: str | None = None
    oidc_client_id: str = ""
    oidc_client_secret: SecretStr | None = None
    oidc_redirect_uri: str | None = None
    oidc_scopes: str = "openid email profile"
    oidc_login_claim: str = "preferred_username"
    oidc_http_timeout_s: float = Field(default=10.0, gt=0)
    oidc_jwks_min_refresh_s: float = Field(default=60.0, ge=0)
    cookie_secure: bool = True
    session_ttl_s: int = Field(default=3600, gt=0)
    session_idle_s: int = Field(default=300, gt=0)

    @property
    def oidc_configured(self) -> bool:
        """True when login has everything discovery and the callback need."""
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_redirect_uri)


@lru_cache
def get_settings() -> Settings:
    return Settings()
