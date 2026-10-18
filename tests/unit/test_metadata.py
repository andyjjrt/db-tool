import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import aiosqlite
import pytest

from db_gateway.metadata import audit, connect, migrate, now_iso, to_iso, transaction


@pytest.fixture
async def conn(tmp_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    connection = await connect(tmp_path / "metadata.sqlite3")
    try:
        await migrate(connection)
        yield connection
    finally:
        await connection.close()


async def test_migration_idempotence_and_pragmas(conn: aiosqlite.Connection) -> None:
    async with conn.execute("SELECT * FROM schema_version") as cur:
        before = list(await cur.fetchall())
    await migrate(conn)
    async with conn.execute("SELECT * FROM schema_version") as cur:
        assert await cur.fetchall() == before
    assert len(before) == 2
    async with conn.execute("PRAGMA journal_mode") as cur:
        assert await cur.fetchone() == ("wal",)
    async with conn.execute("PRAGMA foreign_keys") as cur:
        assert await cur.fetchone() == (1,)
    async with conn.execute("PRAGMA recursive_triggers") as cur:
        assert await cur.fetchone() == (1,)
    async with conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'") as cur:
        assert {row[0] for row in await cur.fetchall()} == {
            "schema_version",
            "users",
            "activations",
            "descriptions",
            "connections",
            "sessions",
            "sync_state",
            "audit_log",
            "web_sessions",
            "oidc_login_states",
        }


async def test_audit_insert_and_append_only(conn: aiosqlite.Connection) -> None:
    await audit.record(conn, "query", sql_text="SELECT 'quoted'", detail={"count": 1})
    async with conn.execute("SELECT kind, sql_text, detail, ts FROM audit_log") as cur:
        row = await cur.fetchone()
    assert row is not None
    assert row[:2] == ("query", "SELECT 'quoted'")
    assert json.loads(row[2]) == {"count": 1}
    assert row[3]
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        await conn.execute("UPDATE audit_log SET error = ?", ("changed",))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        await conn.execute("DELETE FROM audit_log")
    with pytest.raises(sqlite3.IntegrityError):
        await audit.record(conn, "invalid")
    with pytest.raises(ValueError, match="Unknown audit fields"):
        await audit.record(conn, "query", invalid="field")


@pytest.mark.parametrize("detail", [{"key": 1}, [1, "two"], (1, 2), True, 42, 1.5, None, '{"x":1}'])
async def test_audit_json_detail(conn: aiosqlite.Connection, detail: object) -> None:
    async with transaction(conn):
        await audit.record(conn, "admin", detail=detail)
    async with conn.execute("SELECT detail FROM audit_log") as cur:
        row = await cur.fetchone()
    assert row is not None
    if detail is None or isinstance(detail, str):
        assert row[0] == detail
    else:
        assert json.loads(row[0]) == json.loads(json.dumps(detail))


async def test_audit_rejects_backdating_and_invalid_json(conn: aiosqlite.Connection) -> None:
    async with transaction(conn):
        with pytest.raises(ValueError, match="Unknown audit fields: ts"):
            await audit.record(conn, "admin", ts="2020-01-01T00:00:00.000Z")
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            await audit.record(conn, "admin", detail="not json")
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            await conn.execute(
                "INSERT INTO audit_log (kind, detail) VALUES (?, ?)", ("admin", "not json")
            )
        await audit.record(conn, "admin")
    async with conn.execute("SELECT ts FROM audit_log") as cur:
        rows = list(await cur.fetchall())
    assert len(rows) == 1
    assert to_iso(datetime.fromisoformat(rows[0][0])) == rows[0][0]


async def test_activation_revocation(conn: aiosqlite.Connection) -> None:
    await conn.execute("INSERT INTO users (id, login_key) VALUES (?, ?)", (1, "alice"))
    await conn.execute(
        "INSERT INTO activations (user_id, reason, expires_at) VALUES (?, ?, ?)",
        (1, "support", "2026-10-17T00:00:00.000Z"),
    )
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute("UPDATE activations SET reason = ?", ("changed",))
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute("UPDATE activations SET revoked_at = ?", ("2026-10-16T12:00:00.000Z",))
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute(
            "UPDATE activations SET revoked_at = ?, revoked_by = ?, reason = ?",
            ("2026-10-16T12:00:00.000Z", 1, "changed"),
        )
    await conn.execute(
        "UPDATE activations SET revoked_at = ?, revoked_by = ?",
        ("2026-10-16T12:00:00.000Z", 1),
    )
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute(
            "UPDATE activations SET revoked_at = ?, revoked_by = ?",
            ("2026-10-16T13:00:00.000Z", 1),
        )
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute("UPDATE activations SET revoked_at = NULL, revoked_by = NULL")
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute("DELETE FROM activations")


async def test_names_immutable(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        "INSERT INTO connections (name, host, dbname, admin_secret_ref) VALUES (?, ?, ?, ?)",
        ("prod", "localhost", "postgres", "prod-admin"),
    )
    async with conn.execute("SELECT default_privilege_owners FROM connections") as cur:
        assert await cur.fetchone() == ("[]",)
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute("UPDATE connections SET name = ?", ("renamed",))
    await conn.execute("UPDATE connections SET host = ?", ("db.internal",))


@pytest.mark.parametrize("name", ["Upper", "bad name", "bad/name", "1bad", "", "a" * 42, "é"])
async def test_invalid_connection_names(conn: aiosqlite.Connection, name: str) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
        await conn.execute(
            "INSERT INTO connections (name, host, dbname, admin_secret_ref) VALUES (?, ?, ?, ?)",
            (name, "localhost", "postgres", "secret"),
        )


@pytest.mark.parametrize("name", ["a", "prod-main_123", "a" * 41])
async def test_valid_connection_names(conn: aiosqlite.Connection, name: str) -> None:
    await conn.execute(
        "INSERT INTO connections (name, host, dbname, admin_secret_ref) VALUES (?, ?, ?, ?)",
        (name, "localhost", "postgres", "secret"),
    )


@pytest.mark.parametrize("owners", ["not json", "{}", '"owner"', "null", "1"])
async def test_connection_privilege_owners_require_json_array(
    conn: aiosqlite.Connection, owners: str
) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
        await conn.execute(
            "INSERT INTO connections "
            "(name, host, dbname, admin_secret_ref, default_privilege_owners) "
            "VALUES (?, ?, ?, ?, ?)",
            ("prod", "localhost", "postgres", "secret", owners),
        )


async def test_connection_privilege_owners_array(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        "INSERT INTO connections "
        "(name, host, dbname, admin_secret_ref, default_privilege_owners) "
        "VALUES (?, ?, ?, ?, ?)",
        ("prod", "localhost", "postgres", "secret", '["owner", "other_owner"]'),
    )
    async with conn.execute("SELECT default_privilege_owners FROM connections") as cur:
        assert await cur.fetchone() == ('["owner", "other_owner"]',)


async def test_foreign_keys_enforced(conn: aiosqlite.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        await conn.execute(
            "INSERT INTO activations (user_id, reason, expires_at) VALUES (?, ?, ?)",
            (999, "support", "2026-10-17T00:00:00.000Z"),
        )


@pytest.mark.parametrize("verb", ["INSERT OR REPLACE", "REPLACE"])
async def test_audit_replace_rejected(conn: aiosqlite.Connection, verb: str) -> None:
    await audit.record(conn, "admin", sql_text="original")
    async with conn.execute("SELECT * FROM audit_log") as cur:
        before = await cur.fetchall()
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute(
            f"{verb} INTO audit_log (id, kind, sql_text) VALUES (?, ?, ?)",
            (1, "query", "forged"),
        )
    async with conn.execute("SELECT * FROM audit_log") as cur:
        assert await cur.fetchall() == before


@pytest.mark.parametrize("verb", ["INSERT OR REPLACE", "REPLACE"])
async def test_activation_replace_rejected(conn: aiosqlite.Connection, verb: str) -> None:
    await conn.execute("INSERT INTO users (id, login_key) VALUES (?, ?)", (1, "alice"))
    await conn.execute(
        "INSERT INTO activations (id, user_id, reason, expires_at, revoked_at, revoked_by) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (1, 1, "support", "2026-10-17T00:00:00.000Z", "2026-10-16T12:00:00.000Z", 1),
    )
    async with conn.execute("SELECT * FROM activations") as cur:
        before = await cur.fetchall()
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute(
            f"{verb} INTO activations (id, user_id, reason, expires_at) VALUES (?, ?, ?, ?)",
            (1, 1, "forged", "2026-10-17T00:00:00.000Z"),
        )
    async with conn.execute("SELECT * FROM activations") as cur:
        assert await cur.fetchall() == before


async def test_descriptions_allow_upsert_and_delete(conn: aiosqlite.Connection) -> None:
    async with transaction(conn):
        await conn.execute(
            "INSERT INTO descriptions (object, description) VALUES (?, ?)",
            ("group:analysts", "original"),
        )
        async with conn.execute("SELECT updated_at FROM descriptions") as cur:
            row = await cur.fetchone()
        assert row is not None
        assert to_iso(datetime.fromisoformat(row[0])) == row[0]
        await conn.execute(
            "INSERT INTO descriptions (object, description, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(object) DO UPDATE SET "
            "description = excluded.description, updated_at = excluded.updated_at",
            ("group:analysts", "changed", "2026-10-18T12:34:56.000Z"),
        )
        async with conn.execute("SELECT * FROM descriptions") as cur:
            assert await cur.fetchall() == [
                ("group:analysts", "changed", "2026-10-18T12:34:56.000Z")
            ]
        await conn.execute("DELETE FROM descriptions WHERE object = ?", ("group:analysts",))
    async with conn.execute("SELECT * FROM descriptions") as cur:
        assert await cur.fetchall() == []


@pytest.mark.parametrize("object_id, description", [(None, "text"), ("group:a", None)])
async def test_descriptions_require_object_and_text(
    conn: aiosqlite.Connection, object_id: str | None, description: str | None
) -> None:
    async with transaction(conn):
        with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
            await conn.execute(
                "INSERT INTO descriptions (object, description) VALUES (?, ?)",
                (object_id, description),
            )


@pytest.mark.parametrize("verb", ["INSERT OR REPLACE", "REPLACE"])
@pytest.mark.parametrize("conflict", ["id", "name"])
async def test_connection_replace_rejected(
    conn: aiosqlite.Connection, verb: str, conflict: str
) -> None:
    await conn.execute(
        "INSERT INTO connections (id, name, host, dbname, admin_secret_ref) VALUES (?, ?, ?, ?, ?)",
        (1, "original", "localhost", "postgres", "secret"),
    )
    async with conn.execute("SELECT * FROM connections") as cur:
        before = await cur.fetchall()
    with pytest.raises(sqlite3.IntegrityError):
        await conn.execute(
            f"{verb} INTO connections (id, name, host, dbname, admin_secret_ref) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                1 if conflict == "id" else 2,
                "forged" if conflict == "id" else "original",
                "forged",
                "postgres",
                "secret",
            ),
        )
    async with conn.execute("SELECT * FROM connections") as cur:
        assert await cur.fetchall() == before


def test_timestamp_helpers() -> None:
    instant = datetime(2026, 10, 16, 12, 34, 56, 123456, tzinfo=timezone(timedelta(hours=8)))
    assert to_iso(instant) == "2026-10-16T04:34:56.123Z"
    assert to_iso(instant) == to_iso(instant.astimezone(UTC))
    with pytest.raises(ValueError, match="timezone-aware"):
        to_iso(datetime(2026, 10, 16))


async def test_default_timestamp_string_order(conn: aiosqlite.Connection) -> None:
    await conn.execute("INSERT INTO users (login_key) VALUES (?)", ("alice",))
    async with conn.execute("SELECT created_at FROM users") as cur:
        row = await cur.fetchone()
    assert row is not None
    generated = row[0]
    instant = datetime.fromisoformat(generated)
    assert to_iso(instant) == generated
    assert to_iso(instant - timedelta(milliseconds=1)) < generated
    assert generated < to_iso(instant + timedelta(milliseconds=1))
    current = now_iso()
    assert len(current) == 24
    assert to_iso(datetime.fromisoformat(current)) == current


@pytest.mark.parametrize(
    "invalid",
    [
        "2026-10-16 12:34:56",
        "2026-10-16T12:34:56Z",
        "2026-10-16T12:34:56.123456Z",
        "2026-10-16T12:34:56.123+00:00",
        "2026-10-16Txx:yy:zz.abcZ",
    ],
)
async def test_all_timestamp_columns_reject_noncanonical_values(
    conn: aiosqlite.Connection, invalid: str
) -> None:
    valid = "2026-10-16T12:34:56.123Z"
    await conn.execute("INSERT INTO users (id, login_key) VALUES (?, ?)", (1, "alice"))
    await conn.execute(
        "INSERT INTO connections (id, name, host, dbname, admin_secret_ref) VALUES (?, ?, ?, ?, ?)",
        (1, "prod", "localhost", "postgres", "secret"),
    )
    await conn.execute(
        "INSERT INTO activations (id, user_id, reason, expires_at) VALUES (?, ?, ?, ?)",
        (1, 1, "support", valid),
    )
    cases: list[tuple[str, dict[str, object], tuple[str, ...]]] = [
        ("schema_version", {"version": 2}, ("applied_at",)),
        ("users", {"login_key": "bob"}, ("created_at", "disabled_at")),
        (
            "activations",
            {"user_id": 1, "reason": "support", "expires_at": valid},
            ("activated_at", "expires_at", "revoked_at"),
        ),
        ("descriptions", {"object": "group:analysts", "description": "text"}, ("updated_at",)),
        (
            "sessions",
            {"user_id": 1, "activation_id": 1, "connection_id": 1, "valid_until": valid},
            ("started_at", "valid_until", "last_seen_at", "ended_at"),
        ),
        ("sync_state", {"consumer": "syncer"}, ("last_applied_at",)),
        ("audit_log", {"kind": "admin"}, ("ts",)),
    ]
    for table, fields, timestamp_columns in cases:
        for column in timestamp_columns:
            values = {**fields, column: invalid}
            with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
                await conn.execute(
                    f"INSERT INTO {table} ({', '.join(values)}) "
                    f"VALUES ({', '.join('?' for _ in values)})",
                    list(values.values()),
                )


@pytest.mark.parametrize("rollback_second", [False, True])
async def test_concurrent_transactions_are_isolated(
    conn: aiosqlite.Connection, rollback_second: bool
) -> None:
    first_inserted = asyncio.Event()
    second_attempted = asyncio.Event()
    second_inserted = asyncio.Event()
    release_first = asyncio.Event()
    release_second = asyncio.Event()

    async def first() -> None:
        async with transaction(conn):
            await audit.record(conn, "admin", detail='"first:1"')
            first_inserted.set()
            await release_first.wait()
            await audit.record(conn, "admin", detail='"first:2"')

    async def second() -> None:
        await first_inserted.wait()
        second_attempted.set()
        with (
            pytest.raises(RuntimeError, match="rollback second")
            if rollback_second
            else nullcontext()
        ):
            async with transaction(conn):
                await audit.record(conn, "admin", detail='"second:1"')
                second_inserted.set()
                await release_second.wait()
                await audit.record(conn, "admin", detail='"second:2"')
                if rollback_second:
                    raise RuntimeError("rollback second")

    async with asyncio.timeout(5), asyncio.TaskGroup() as tasks:
        tasks.create_task(first())
        tasks.create_task(second())
        await second_attempted.wait()
        async with conn.execute("SELECT detail FROM audit_log ORDER BY id") as cur:
            assert [json.loads(row[0]) for row in await cur.fetchall()] == ["first:1"]
        release_first.set()
        await second_inserted.wait()
        async with conn.execute("SELECT detail FROM audit_log ORDER BY id") as cur:
            assert [json.loads(row[0]) for row in await cur.fetchall()] == [
                "first:1",
                "first:2",
                "second:1",
            ]
        release_second.set()

    async with conn.execute("SELECT detail FROM audit_log ORDER BY id") as cur:
        assert [json.loads(row[0]) for row in await cur.fetchall()] == (
            ["first:1", "first:2"]
            if rollback_second
            else ["first:1", "first:2", "second:1", "second:2"]
        )
    # A rollback must release the lock and leave the connection usable.
    async with transaction(conn):
        await audit.record(conn, "admin", detail='"after"')
    async with conn.execute("SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1") as cur:
        assert await cur.fetchone() == ('"after"',)
