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


def test_settings_environment_and_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DBGW_METADATA_DB_PATH", str(tmp_path / "metadata.sqlite3"))
    monkeypatch.setenv("DBGW_OPENFGA_STORE_ID", "store")
    monkeypatch.setenv("DBGW_OPENFGA_MODEL_ID", "model")
    monkeypatch.setenv("DBGW_OPENFGA_API_URL", "http://fga:8080")
    monkeypatch.setenv("DBGW_SYNC_POLL_INTERVAL_S", "3.5")
    monkeypatch.setenv("DBGW_RECONCILE_INTERVAL_S", "42")
    monkeypatch.setenv("DBGW_REVOKE_SYNC_TIMEOUT_S", "7")
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
