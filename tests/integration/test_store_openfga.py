from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from types import SimpleNamespace

import httpx
import pytest

from db_gateway.permissions import store_openfga
from db_gateway.permissions.store import (
    ContinuationTokenInvalid,
    PermissionStore,
    PermissionStoreUnavailable,
)
from db_gateway.permissions.store_openfga import OpenFgaStore
from tests.unit.test_store_contract import StoreContract

pytestmark = pytest.mark.integration


async def _http_error_server(status: int, code: str) -> tuple[asyncio.Server, int]:
    async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        reason = "Bad Request" if status == 400 else "Internal Server Error"
        body = json.dumps({"code": code, "message": "stubbed OpenFGA error"}).encode()
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(respond, "127.0.0.1", 0)
    sockets = server.sockets
    assert sockets is not None
    return server, sockets[0].getsockname()[1]


class TestOpenFgaStoreContract(StoreContract):
    @pytest.fixture
    async def store(self, openfga_url: str, fga_store: str) -> AsyncIterator[PermissionStore]:
        permission_store = OpenFgaStore(openfga_url, fga_store)
        await permission_store.ensure_model()
        try:
            yield permission_store
        finally:
            await permission_store.aclose()


async def test_ensure_model_is_idempotent(openfga_url: str, fga_store: str) -> None:
    store = OpenFgaStore(openfga_url, fga_store)
    try:
        first_id = await store.ensure_model()
        async with httpx.AsyncClient(base_url=openfga_url, timeout=10.0) as client:
            before = await client.get(f"/stores/{fga_store}/authorization-models")
            before.raise_for_status()
            first_count = len(before.json()["authorization_models"])

            second_id = await store.ensure_model()

            after = await client.get(f"/stores/{fga_store}/authorization-models")
            after.raise_for_status()
            second_count = len(after.json()["authorization_models"])
        assert second_id == first_id
        assert second_count == first_count == 1
    finally:
        await store.aclose()


async def test_ensure_model_replaces_a_different_latest_model(
    openfga_url: str, fga_store: str
) -> None:
    async with httpx.AsyncClient(base_url=openfga_url, timeout=10.0) as client:
        response = await client.post(
            f"/stores/{fga_store}/authorization-models",
            json={"schema_version": "1.1", "type_definitions": [{"type": "user"}]},
        )
    response.raise_for_status()
    old_model_id = response.json()["authorization_model_id"]

    store = OpenFgaStore(openfga_url, fga_store)
    try:
        new_model_id = await store.ensure_model()
        assert new_model_id != old_model_id
        async with httpx.AsyncClient(base_url=openfga_url, timeout=10.0) as client:
            models = await client.get(f"/stores/{fga_store}/authorization-models")
        models.raise_for_status()
        assert len(models.json()["authorization_models"]) == 2
    finally:
        await store.aclose()


async def test_ensure_model_rewrites_when_schema_version_differs(
    openfga_url: str,
    fga_store: str,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"schema_version": "1.1", "type_definitions": [{"type": "user"}]}
    model_path = tmp_path / "model.json"
    await asyncio.to_thread(model_path.write_text, json.dumps(expected), encoding="utf-8")
    monkeypatch.setattr(store_openfga, "_MODEL_PATH", model_path)

    store = OpenFgaStore(openfga_url, fga_store)
    writes = []

    async def read_latest() -> SimpleNamespace:
        return SimpleNamespace(
            authorization_model={
                "id": "old-model",
                "schema_version": "1.0",
                "type_definitions": [{"type": "user"}],
                "conditions": {},
            }
        )

    async def write_model(body: object) -> SimpleNamespace:
        writes.append(body)
        return SimpleNamespace(authorization_model_id="new-model")

    monkeypatch.setattr(store._client, "read_latest_authorization_model", read_latest)
    monkeypatch.setattr(store._client, "write_authorization_model", write_model)
    try:
        new_model_id = await store.ensure_model()
        assert new_model_id == "new-model"
        assert len(writes) == 1
    finally:
        await store.aclose()


async def test_ensure_model_rewrites_when_conditions_differ(
    openfga_url: str, fga_store: str
) -> None:
    store = OpenFgaStore(openfga_url, fga_store)
    try:
        first_id = await store.ensure_model()
        async with httpx.AsyncClient(base_url=openfga_url, timeout=10.0) as client:
            current = await client.get(f"/stores/{fga_store}/authorization-models/{first_id}")
            current.raise_for_status()
            model = current.json()["authorization_model"]
            conditioned = await client.post(
                f"/stores/{fga_store}/authorization-models",
                json={
                    "schema_version": model["schema_version"],
                    "type_definitions": model["type_definitions"],
                    "conditions": {
                        "always": {
                            "name": "always",
                            "expression": "true",
                            "parameters": {},
                        }
                    },
                },
            )
            conditioned.raise_for_status()
            conditioned_id = conditioned.json()["authorization_model_id"]

        new_id = await store.ensure_model()
        assert conditioned_id != first_id
        assert new_id not in (first_id, conditioned_id)
    finally:
        await store.aclose()


async def test_invalid_continuation_token_reports_server_error_code(
    openfga_url: str, fga_store: str
) -> None:
    store = OpenFgaStore(openfga_url, fga_store)
    try:
        await store.ensure_model()
        with pytest.raises(ContinuationTokenInvalid, match="invalid_continuation_token"):
            await store.read_changes("not-a-valid-token")
    finally:
        await store.aclose()


async def test_non_token_read_changes_400_maps_to_value_error(fga_store: str) -> None:
    server, port = await _http_error_server(400, "validation_error")
    store = OpenFgaStore(f"http://127.0.0.1:{port}", fga_store)
    try:
        with pytest.raises(ValueError, match="validation_error"):
            await store.read_changes(None)
    finally:
        await store.aclose()
        server.close()
        await server.wait_closed()


async def test_openfga_5xx_maps_to_unavailable(fga_store: str) -> None:
    server, port = await _http_error_server(500, "internal_error")
    store = OpenFgaStore(f"http://127.0.0.1:{port}", fga_store)
    try:
        with pytest.raises(PermissionStoreUnavailable):
            await store.ensure_model()
    finally:
        await store.aclose()
        server.close()
        await server.wait_closed()


async def test_unreachable_openfga_maps_to_unavailable(fga_store: str) -> None:
    store = OpenFgaStore("http://127.0.0.1:1", fga_store)
    try:
        with pytest.raises(PermissionStoreUnavailable):
            await store.ensure_model()
    finally:
        await store.aclose()
