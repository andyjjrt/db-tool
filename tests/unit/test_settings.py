from pathlib import Path

import pytest

from db_gateway.secrets import SecretLookup, get_secret
from db_gateway.settings import Settings, get_settings


def test_settings_defaults() -> None:
    settings = Settings(_env_file=None)  # pyright: ignore[reportCallIssue]
    assert settings.metadata_db_path == Path("var/metadata.sqlite3")
    assert settings.openfga_api_url == "http://localhost:58080"
    assert settings.openfga_store_id is None
    assert settings.openfga_model_id is None
    assert settings.sync_poll_interval_s == 2.0
    assert settings.reconcile_interval_s == 600.0
    assert settings.revoke_sync_timeout_s == 5.0
    assert settings.oidc_issuer is None
    assert settings.oidc_client_id == ""
    assert settings.oidc_client_secret is None
    assert settings.oidc_redirect_uri is None
    assert settings.oidc_scopes == "openid email profile"
    assert settings.oidc_login_claim == "preferred_username"
    assert settings.oidc_http_timeout_s == 10.0
    assert settings.oidc_jwks_min_refresh_s == 60.0
    assert settings.cookie_secure is True
    assert settings.session_ttl_s == 3600
    assert settings.session_idle_s == 300
    assert settings.oidc_configured is False


def test_settings_environment_and_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DBGW_METADATA_DB_PATH", str(tmp_path / "metadata.sqlite3"))
    monkeypatch.setenv("DBGW_OPENFGA_STORE_ID", "store")
    monkeypatch.setenv("DBGW_OPENFGA_MODEL_ID", "model")
    monkeypatch.setenv("DBGW_OPENFGA_API_URL", "http://fga:8080")
    monkeypatch.setenv("DBGW_SYNC_POLL_INTERVAL_S", "3.5")
    monkeypatch.setenv("DBGW_RECONCILE_INTERVAL_S", "42")
    monkeypatch.setenv("DBGW_REVOKE_SYNC_TIMEOUT_S", "7")
    monkeypatch.setenv("DBGW_OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setenv("DBGW_OIDC_CLIENT_ID", "gateway")
    monkeypatch.setenv("DBGW_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("DBGW_OIDC_REDIRECT_URI", "https://gateway.test/auth/callback")
    monkeypatch.setenv("DBGW_OIDC_SCOPES", "openid email")
    monkeypatch.setenv("DBGW_OIDC_LOGIN_CLAIM", "email")
    monkeypatch.setenv("DBGW_OIDC_HTTP_TIMEOUT_S", "4.5")
    monkeypatch.setenv("DBGW_OIDC_JWKS_MIN_REFRESH_S", "5.5")
    monkeypatch.setenv("DBGW_COOKIE_SECURE", "false")
    monkeypatch.setenv("DBGW_SESSION_TTL_S", "120")
    monkeypatch.setenv("DBGW_SESSION_IDLE_S", "30")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings is get_settings()
        assert settings.metadata_db_path == tmp_path / "metadata.sqlite3"
        assert settings.openfga_store_id == "store"
        assert settings.openfga_model_id == "model"
        assert settings.openfga_api_url == "http://fga:8080"
        assert settings.sync_poll_interval_s == 3.5
        assert settings.reconcile_interval_s == 42
        assert settings.revoke_sync_timeout_s == 7
        assert settings.oidc_issuer == "https://issuer.test"
        assert settings.oidc_client_id == "gateway"
        assert settings.oidc_client_secret is not None
        assert settings.oidc_client_secret.get_secret_value() == "secret"
        assert settings.oidc_redirect_uri == "https://gateway.test/auth/callback"
        assert settings.oidc_scopes == "openid email"
        assert settings.oidc_login_claim == "email"
        assert settings.oidc_http_timeout_s == 4.5
        assert settings.oidc_jwks_min_refresh_s == 5.5
        assert settings.cookie_secure is False
        assert settings.session_ttl_s == 120
        assert settings.session_idle_s == 30
        assert settings.oidc_configured is True
    finally:
        get_settings.cache_clear()


def test_secret_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup: SecretLookup = get_secret
    monkeypatch.setenv("DBGW_SECRET_PROD_ADMIN", "secret")
    assert lookup("prod-admin") == "secret"
    assert lookup("prod_admin") == "secret"
    monkeypatch.delenv("DBGW_SECRET_PROD_ADMIN")
    with pytest.raises(KeyError, match="DBGW_SECRET_PROD_ADMIN"):
        lookup("prod-admin")


def test_empty_secret_reference_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBGW_SECRET_", "must not be returned")
    with pytest.raises(ValueError, match="must not be empty"):
        get_secret("")
