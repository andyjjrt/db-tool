import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from db_gateway.app import create_app
from db_gateway.settings import get_settings


def test_health_and_metadata_lifecycle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "nested" / "metadata.sqlite3"
    monkeypatch.setenv("DBGW_METADATA_DB_PATH", str(path))
    get_settings.cache_clear()
    try:
        app = create_app()
        with TestClient(app) as client:
            response = client.get("/healthz")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}
            assert path.exists()

            async def schema_version() -> list[tuple[int]]:
                async with app.state.metadata.execute("SELECT version FROM schema_version") as cur:
                    return await cur.fetchall()

            assert client.portal is not None
            assert client.portal.call(schema_version) == [(1,)]
        with pytest.raises(ValueError, match="no active connection"):
            asyncio.run(schema_version())
    finally:
        get_settings.cache_clear()
