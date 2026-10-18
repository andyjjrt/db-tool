"""Unit tests for the users data-access helpers and login_key validation (no services)."""

import sqlite3
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import aiosqlite
import pytest

from db_gateway import metadata
from db_gateway.api.admin_users import clean_login_key
from db_gateway.metadata import users
from db_gateway.permissions.ids import InvalidInput


@pytest.fixture
async def conn(tmp_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    connection = await metadata.connect(tmp_path / "metadata.sqlite3")
    try:
        await metadata.migrate(connection)
        yield connection
    finally:
        await connection.close()


async def test_insert_get_and_defaults(conn: aiosqlite.Connection) -> None:
    row = await users.insert(conn, "alice", email="a@example.com", display_name="Alice")
    assert row.login_key == "alice"
    assert row.email == "a@example.com"
    assert row.display_name == "Alice"
    assert row.pg_role_name is None
    assert row.disabled_at is None
    assert row.last_oidc_sub is None
    assert row.oidc_sub is None
    assert metadata.to_iso(datetime.fromisoformat(row.created_at)) == row.created_at
    assert await users.get_by_id(conn, row.id) == row
    assert await users.get_by_login_key(conn, "alice") == row
    assert await users.get_by_login_key(conn, "ALICE") is None
    assert await users.get_by_id(conn, row.id + 1000) is None


async def test_insert_duplicate_login_key_raises(conn: aiosqlite.Connection) -> None:
    await users.insert(conn, "alice")
    with pytest.raises(sqlite3.IntegrityError):
        await users.insert(conn, "alice")


async def test_list_orders_by_login_key_and_filters_disabled(conn: aiosqlite.Connection) -> None:
    for login_key in ("bob", "Alice", "carl"):
        await users.insert(conn, login_key)
    bob = await users.get_by_login_key(conn, "bob")
    assert bob is not None
    disabled = await users.set_disabled(conn, bob.id, True)
    assert disabled is not None
    assert [row.login_key for row in await users.list(conn)] == ["Alice", "bob", "carl"]
    assert [
        row.login_key for row in await users.list(conn, include_disabled=False)
    ] == ["Alice", "carl"]


async def test_update_sets_only_given_columns(conn: aiosqlite.Connection) -> None:
    row = await users.insert(conn, "alice", email="a@example.com", display_name="Alice")
    updated = await users.update(conn, row.id, {"display_name": "Alice A."})
    assert updated == replace(row, display_name="Alice A.")
    cleared = await users.update(conn, row.id, {"email": None})
    assert cleared is not None
    assert cleared.email is None and cleared.display_name == "Alice A."
    assert await users.update(conn, row.id, {}) == cleared
    assert await users.update(conn, row.id + 999, {"display_name": "x"}) is None
    for unknown in (
        {"id": "5"},
        {"pg_role_name": "r"},
        {"created_at": "x"},
        {"oidc_sub": "subject-1"},
    ):
        with pytest.raises(ValueError, match="not editable users columns"):
            await users.update(conn, row.id, unknown)


async def test_set_disabled_stamps_and_clears_iso(conn: aiosqlite.Connection) -> None:
    row = await users.insert(conn, "alice")
    disabled = await users.set_disabled(conn, row.id, True)
    assert disabled is not None
    assert disabled.disabled_at is not None
    assert metadata.to_iso(datetime.fromisoformat(disabled.disabled_at)) == disabled.disabled_at
    again = await users.set_disabled(conn, row.id, True)
    assert again is not None
    assert again.disabled_at == disabled.disabled_at  # repeats keep the first stamp
    enabled = await users.set_disabled(conn, row.id, False)
    assert enabled is not None
    assert enabled.disabled_at is None
    assert await users.set_disabled(conn, row.id + 999, True) is None


async def test_unbind_clears_the_bound_subject(conn: aiosqlite.Connection) -> None:
    row = await users.insert(conn, "alice", email="a@example.com")
    await conn.execute("UPDATE users SET oidc_sub = ? WHERE id = ?", ("subject-1", row.id))
    bound = await users.get_by_id(conn, row.id)
    assert bound is not None and bound.oidc_sub == "subject-1"
    unbound = await users.unbind(conn, row.id)
    assert unbound is not None
    assert unbound.oidc_sub is None
    assert unbound.email == "a@example.com"
    assert await users.unbind(conn, row.id + 999) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (" bob ", "bob"),
        ("Bob", "Bob"),
        ("a" * 255, "a" * 255),
        ("jos-1_x.y", "jos-1_x.y"),
    ],
)
def test_clean_login_key_strips_and_keeps_case(value: str, expected: str) -> None:
    assert clean_login_key(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "   ", "\t", "a b", "a\tb", "a\nb", "\x00", "\x7f", "a\u200bb", "a" * 256],
)
def test_clean_login_key_rejects_invalid_values(value: str) -> None:
    with pytest.raises(InvalidInput):
        clean_login_key(value)
