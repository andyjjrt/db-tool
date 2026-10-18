"""Unit tests for RuleService (plan §2.4): write-time checks, OpenFGA writes and audit."""

import asyncio
import json
from collections.abc import AsyncIterator, Sequence
from typing import Any, Literal

import aiosqlite
import pytest

from db_gateway import metadata
from db_gateway.permissions import ids
from db_gateway.permissions.admin import AdminForbidden, AdminUser, admin_tuple
from db_gateway.permissions.context import ConnectionLocks
from db_gateway.permissions.rules import NotFound, RuleConflict, RuleService
from db_gateway.permissions.store import PermissionStoreUnavailable, Tuple
from db_gateway.permissions.store_memory import MemoryStore
from db_gateway.permissions.types import (
    CreateGroupRole,
    DisableRowPolicy,
    DropGroupRole,
    EnableRowPolicy,
    PgOp,
)

INITIAL = AdminUser(1, "boss")
ORDINARY = AdminUser(2, "helper")
PLAIN = AdminUser(3, "plain")


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[PgOp]]] = []
        self.fail_on: set[str] = set()
        self.skip_all = False

    async def apply(self, connection: str, ops: Sequence[PgOp]) -> Sequence[PgOp]:
        self.calls.append((connection, list(ops)))
        if connection in self.fail_on:
            raise RuntimeError(f"boom on {connection}")
        return list(ops) if self.skip_all else []


class FakeStats:
    def __init__(self) -> None:
        self.count = 3
        self.calls: list[tuple[str, str, str, str, int]] = []

    async def distinct_count(
        self, connection: str, schema: str, table: str, column: str, limit: int
    ) -> int:
        self.calls.append((connection, schema, table, column, limit))
        return self.count


@pytest.fixture
async def db() -> AsyncIterator[aiosqlite.Connection]:
    conn = await metadata.connect(":memory:")
    try:
        await metadata.migrate(conn)
        async with metadata.transaction(conn):
            for user_id, key in ((1, "boss"), (2, "helper"), (3, "plain"), (4, "other")):
                await conn.execute(
                    "INSERT INTO users (id, login_key) VALUES (?, ?)", (user_id, key)
                )
            for name in ("prod", "dev"):
                await conn.execute(
                    "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
                    "VALUES (?, 'h', 'd', 'ref')",
                    (name,),
                )
        yield conn
    finally:
        await conn.close()


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def executor() -> FakeExecutor:
    return FakeExecutor()


@pytest.fixture
def stats() -> FakeStats:
    return FakeStats()


@pytest.fixture
def svc(
    db: aiosqlite.Connection, store: MemoryStore, executor: FakeExecutor, stats: FakeStats
) -> RuleService:
    return RuleService(db, store, executor, stats, distinct_limit=10, initial_admins={"boss"})


class FailingRowColumnStore(MemoryStore):
    """MemoryStore whose write raises when it carries a row_column tuple."""

    async def write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
        if any(t.relation == "row_column" for t in writes):
            raise PermissionStoreUnavailable("openfga down")
        await super().write(writes, deletes)


def row_column(column: str, table: str = "t") -> Tuple:
    return Tuple(ids.column(column), "row_column", ids.db_table("prod", "public", table))


async def audit_rows(db: aiosqlite.Connection) -> list[dict[str, Any]]:
    async with db.execute(
        "SELECT kind, user_id, connection_id, error, detail FROM audit_log ORDER BY id"
    ) as cur:
        return [
            {"kind": k, "user_id": u, "connection_id": c, "error": e, "detail": json.loads(d)}
            for k, u, c, e, d in await cur.fetchall()
        ]


async def count(db: aiosqlite.Connection, table: str) -> int:
    async with db.execute(f"SELECT count(*) FROM {table}") as cur:  # noqa: S608 - test constant
        row = await cur.fetchone()
    assert row is not None
    return row[0]


async def make_group(svc: RuleService, name: str = "g1") -> None:
    await svc.create_group(INITIAL, name, None)


# --- §2.4 checks -------------------------------------------------------------------


async def test_schema_then_table_reader_conflicts(svc: RuleService, store: MemoryStore) -> None:
    await make_group(svc)
    await svc.grant_schema_reader(INITIAL, "g1", "prod", "public")
    with pytest.raises(RuleConflict, match="whole schema prod/public"):
        await svc.grant_table_reader(INITIAL, "g1", "prod", "public", "t")
    assert await store.read(ids.db_table("prod", "public", "t")) == []


async def test_table_then_schema_reader_conflicts(svc: RuleService, store: MemoryStore) -> None:
    await make_group(svc)
    await svc.grant_table_reader(INITIAL, "g1", "prod", "public", "t")
    with pytest.raises(RuleConflict, match="reads table t"):
        await svc.grant_schema_reader(INITIAL, "g1", "prod", "public")
    assert await store.read(ids.db_schema("prod", "public")) == []


async def test_schema_and_table_in_other_scopes_do_not_conflict(svc: RuleService) -> None:
    await make_group(svc)
    await make_group(svc, "g2")
    await svc.grant_schema_reader(INITIAL, "g1", "prod", "public")
    await svc.grant_table_reader(INITIAL, "g1", "prod", "other", "t")  # other schema
    await svc.grant_table_reader(INITIAL, "g1", "dev", "public", "t")  # other connection
    await svc.grant_table_reader(INITIAL, "g2", "prod", "public", "t")  # other group


async def test_row_set_on_undeclared_table_conflicts(svc: RuleService) -> None:
    await make_group(svc)
    with pytest.raises(RuleConflict, match="not declared"):
        await svc.grant_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")


async def test_row_set_on_wrong_column_conflicts(svc: RuleService) -> None:
    await make_group(svc)
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    with pytest.raises(RuleConflict, match="column team, not region"):
        await svc.grant_row_set(INITIAL, "g1", "prod", "public", "t", "region", "a")


async def test_undeclare_with_row_set_readers_conflicts(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore
) -> None:
    await make_group(svc)
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    await svc.grant_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
    executor.calls.clear()
    with pytest.raises(RuleConflict, match="row_set readers"):
        await svc.undeclare_row_policy(INITIAL, "prod", "public", "t")
    assert executor.calls == []
    assert await store.read(ids.db_table("prod", "public", "t"), "row_column") == [
        row_column("team")
    ]
    await svc.revoke_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
    await svc.undeclare_row_policy(INITIAL, "prod", "public", "t")
    assert executor.calls == [("prod", [DisableRowPolicy("public", "t")])]
    assert await store.read(ids.db_table("prod", "public", "t"), "row_column") == []


async def test_undeclare_unknown_table_not_found(svc: RuleService) -> None:
    with pytest.raises(NotFound):
        await svc.undeclare_row_policy(INITIAL, "prod", "public", "t")


async def test_declare_over_distinct_limit_conflicts(
    svc: RuleService, stats: FakeStats, executor: FakeExecutor, store: MemoryStore
) -> None:
    stats.count = 11
    with pytest.raises(RuleConflict, match="more than 10"):
        await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    assert stats.calls == [("prod", "public", "t", "team", 10)]
    assert executor.calls == []
    assert await store.read(ids.db_table("prod", "public", "t"), "row_column") == []
    stats.count = 10
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")


async def test_declare_twice_conflicts(svc: RuleService) -> None:
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    with pytest.raises(RuleConflict, match="already row-controlled"):
        await svc.declare_row_policy(INITIAL, "prod", "public", "t", "region")


async def test_delete_group_with_rules_conflicts(svc: RuleService, store: MemoryStore) -> None:
    await make_group(svc)
    await svc.add_member(INITIAL, "g1", 4)
    await svc.grant_table_reader(INITIAL, "g1", "prod", "public", "t")
    with pytest.raises(RuleConflict, match="still has rules"):
        await svc.delete_group(INITIAL, "g1")
    assert await store.read(ids.group("g1"), "member") != []  # nothing was removed
    await svc.revoke_table_reader(INITIAL, "g1", "prod", "public", "t")
    await svc.delete_group(INITIAL, "g1")


@pytest.mark.parametrize("kind", ["schema", "row_set"])
async def test_delete_group_blocked_by_each_reader_type(svc: RuleService, kind: str) -> None:
    await make_group(svc)
    if kind == "schema":
        await svc.grant_schema_reader(INITIAL, "g1", "prod", "public")
    else:
        await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
        await svc.grant_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
    with pytest.raises(RuleConflict):
        await svc.delete_group(INITIAL, "g1")


# --- validation --------------------------------------------------------------------


async def test_wildcard_rejected_everywhere(svc: RuleService) -> None:
    await make_group(svc)
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    calls = [
        svc.grant_schema_reader(INITIAL, "g1", "prod", "*"),
        svc.revoke_schema_reader(INITIAL, "g1", "prod", "*"),
        svc.grant_table_reader(INITIAL, "g1", "prod", "*", "t"),
        svc.grant_table_reader(INITIAL, "g1", "prod", "public", "*"),
        svc.revoke_table_reader(INITIAL, "g1", "prod", "public", "*"),
        svc.grant_row_set(INITIAL, "g1", "prod", "*", "t", "team", "a"),
        svc.grant_row_set(INITIAL, "g1", "prod", "public", "*", "team", "a"),
        svc.grant_row_set(INITIAL, "g1", "prod", "public", "t", "*", "a"),
        svc.grant_row_set(INITIAL, "g1", "prod", "public", "t", "team", "*"),
        svc.revoke_row_set(INITIAL, "g1", "prod", "public", "t", "team", "*"),
        svc.declare_row_policy(INITIAL, "prod", "*", "t", "team"),
        svc.declare_row_policy(INITIAL, "prod", "public", "*", "team"),
        svc.declare_row_policy(INITIAL, "prod", "public", "u", "*"),
        svc.undeclare_row_policy(INITIAL, "prod", "public", "*"),
    ]
    for call in calls:
        with pytest.raises(ValueError, match="'\\*'"):
            await call


async def test_unknown_names_not_found(svc: RuleService) -> None:
    await make_group(svc)
    with pytest.raises(NotFound):
        await svc.grant_schema_reader(INITIAL, "nope", "prod", "public")
    with pytest.raises(NotFound):
        await svc.grant_schema_reader(INITIAL, "g1", "nope", "public")
    with pytest.raises(NotFound):
        await svc.add_member(INITIAL, "g1", 999)
    with pytest.raises(NotFound):
        await svc.add_member(INITIAL, "nope", 4)
    with pytest.raises(NotFound):
        await svc.declare_row_policy(INITIAL, "nope", "public", "t", "team")
    with pytest.raises(NotFound):
        await svc.delete_group(INITIAL, "nope")


async def test_create_group_validation(svc: RuleService) -> None:
    for bad in ("", "Upper", "1abc", "a-b", "x" * 42, "*"):
        with pytest.raises(ValueError, match="invalid group name"):
            await svc.create_group(INITIAL, bad, None)
    await make_group(svc)
    with pytest.raises(RuleConflict, match="already exists"):
        await make_group(svc)


# --- row_set parent tuple ----------------------------------------------------------


async def test_row_set_parent_tuple_follows_first_and_last_reader(
    svc: RuleService, store: MemoryStore
) -> None:
    await make_group(svc, "g1")
    await make_group(svc, "g2")
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    set_id = ids.row_set("prod", "public", "t", "team", "a")
    parent = Tuple(ids.db_table("prod", "public", "t"), "table", set_id)

    await svc.grant_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
    assert parent in await store.read(set_id)
    await svc.grant_row_set(INITIAL, "g2", "prod", "public", "t", "team", "a")
    await svc.revoke_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
    assert parent in await store.read(set_id)  # g2 still reads it
    await svc.revoke_row_set(INITIAL, "g2", "prod", "public", "t", "team", "a")
    assert await store.read(set_id) == []


# --- declare / undeclare against the executor ----------------------------------------


async def test_declare_success_writes_tuple_and_enables_policy(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore, db: aiosqlite.Connection
) -> None:
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    assert executor.calls == [("prod", [EnableRowPolicy("public", "t", "team")])]
    assert await store.read(ids.db_table("prod", "public", "t"), "row_column") == [
        row_column("team")
    ]
    (row,) = await audit_rows(db)
    assert row["error"] is None
    assert row["detail"]["action"] == "declare_row_policy"
    assert row["detail"]["written"] == [
        {
            "user": "column:team",
            "relation": "row_column",
            "object": "db_table:prod/public/t",
        }
    ]


async def test_declare_executor_failure_writes_nothing_and_audits(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore, db: aiosqlite.Connection
) -> None:
    executor.fail_on = {"prod"}
    with pytest.raises(RuntimeError, match="boom"):
        await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    assert await store.read() == []
    (row,) = await audit_rows(db)
    assert row["detail"]["action"] == "declare_row_policy"
    assert "boom" in row["error"]
    assert "boom" in row["detail"]["error"]
    executor.fail_on = set()
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")  # can retry


async def test_declare_skipped_by_executor_writes_nothing_and_audits(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore, db: aiosqlite.Connection
) -> None:
    executor.skip_all = True  # e.g. the table vanished after the distinct count
    with pytest.raises(NotFound, match="not enabled"):
        await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    assert await store.read() == []
    (row,) = await audit_rows(db)
    assert "not enabled" in row["detail"]["error"]


async def test_declare_store_failure_undoes_policy_and_audits(
    db: aiosqlite.Connection, executor: FakeExecutor, stats: FakeStats
) -> None:
    store = FailingRowColumnStore()
    svc = RuleService(db, store, executor, stats, distinct_limit=10, initial_admins={"boss"})
    with pytest.raises(PermissionStoreUnavailable):
        await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    assert executor.calls == [
        ("prod", [EnableRowPolicy("public", "t", "team")]),
        ("prod", [DisableRowPolicy("public", "t")]),
    ]
    assert await store.read() == []
    (row,) = await audit_rows(db)
    assert "openfga down" in row["error"]
    assert "undo failed" not in row["error"]


async def test_declare_store_failure_and_failed_undo_report_both(
    db: aiosqlite.Connection, stats: FakeStats
) -> None:
    class UndoFails(FakeExecutor):
        async def apply(self, connection: str, ops: Sequence[PgOp]) -> Sequence[PgOp]:
            if isinstance(ops[0], DisableRowPolicy):
                raise RuntimeError("undo boom")
            return await super().apply(connection, ops)

    svc = RuleService(
        db, FailingRowColumnStore(), UndoFails(), stats, distinct_limit=10, initial_admins=set()
    )
    with pytest.raises(PermissionStoreUnavailable):
        await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    (row,) = await audit_rows(db)
    assert "openfga down" in row["error"]
    assert "undo boom" in row["error"]


async def test_declare_store_failure_and_skipped_undo_is_audited(
    db: aiosqlite.Connection, stats: FakeStats
) -> None:
    class UndoSkipped(FakeExecutor):
        async def apply(self, connection: str, ops: Sequence[PgOp]) -> Sequence[PgOp]:
            await super().apply(connection, ops)
            return list(ops) if isinstance(ops[0], DisableRowPolicy) else []

    svc = RuleService(
        db, FailingRowColumnStore(), UndoSkipped(), stats, distinct_limit=10, initial_admins=set()
    )
    with pytest.raises(PermissionStoreUnavailable):
        await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    (row,) = await audit_rows(db)
    assert "openfga down" in row["error"]
    assert "undo skipped" in row["error"]


async def test_redeclare_with_other_column_conflicts(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore
) -> None:
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    executor.calls.clear()
    with pytest.raises(RuleConflict, match="already row-controlled by column team"):
        await svc.declare_row_policy(INITIAL, "prod", "public", "t", "region")
    assert executor.calls == []
    assert await store.read(ids.db_table("prod", "public", "t"), "row_column") == [
        row_column("team")
    ]


async def test_undeclare_success_deletes_tuple_and_disables_policy(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore, db: aiosqlite.Connection
) -> None:
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    executor.calls.clear()
    assert await svc.undeclare_row_policy(INITIAL, "prod", "public", "t") is None
    assert executor.calls == [("prod", [DisableRowPolicy("public", "t")])]
    assert await store.read() == []
    rows = await audit_rows(db)
    assert rows[1]["error"] is None
    assert rows[1]["detail"]["deleted"][0]["relation"] == "row_column"


async def test_undeclare_executor_failure_keeps_delete_and_reports_pending(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore, db: aiosqlite.Connection
) -> None:
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    executor.fail_on = {"prod"}
    pending = await svc.undeclare_row_policy(INITIAL, "prod", "public", "t")
    assert pending is not None
    assert "boom" in pending
    assert await store.read() == []
    rows = await audit_rows(db)
    assert len(rows) == 2
    assert "boom" in rows[1]["error"]


async def test_undeclare_skipped_by_executor_reports_pending(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore, db: aiosqlite.Connection
) -> None:
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    executor.skip_all = True
    assert await svc.undeclare_row_policy(INITIAL, "prod", "public", "t") is not None
    assert await store.read() == []
    assert (await audit_rows(db))[1]["error"] is not None


async def test_undeclare_blocked_by_row_set_parent_tuple(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore, db: aiosqlite.Connection
) -> None:
    await svc.declare_row_policy(INITIAL, "prod", "public", "t", "team")
    parent = Tuple(
        ids.db_table("prod", "public", "t"),
        "table",
        ids.row_set("prod", "public", "t", "team", "a"),
    )
    await store.write([parent])  # a row_set exists iff its parent tuple does
    executor.calls.clear()
    with pytest.raises(RuleConflict, match="row_set readers"):
        await svc.undeclare_row_policy(INITIAL, "prod", "public", "t")
    assert executor.calls == []
    assert row_column("team") in await store.read()
    assert len(await audit_rows(db)) == 1  # only the declare


# --- groups on every connection --------------------------------------------------------


async def test_create_and_delete_group_reach_every_connection(
    svc: RuleService, executor: FakeExecutor, store: MemoryStore, db: aiosqlite.Connection
) -> None:
    assert await svc.create_group(INITIAL, "g1", "desc") == {}
    assert executor.calls == [
        ("prod", [CreateGroupRole("g_g1")]),
        ("dev", [CreateGroupRole("g_g1")]),
    ]
    await svc.add_member(INITIAL, "g1", 4)
    executor.calls.clear()
    assert await svc.delete_group(INITIAL, "g1") == {}
    assert executor.calls == [
        ("prod", [DropGroupRole("g_g1")]),
        ("dev", [DropGroupRole("g_g1")]),
    ]
    assert await store.read(ids.group("g1"), "member") == []
    assert await count(db, "groups") == 0


async def test_failing_connection_is_reported_and_group_kept(
    svc: RuleService, executor: FakeExecutor, db: aiosqlite.Connection
) -> None:
    executor.fail_on = {"dev"}
    failed = await svc.create_group(INITIAL, "g1", None)
    assert list(failed) == ["dev"]
    assert "boom" in failed["dev"]
    assert await count(db, "groups") == 1
    assert [c for c, _ in executor.calls] == ["prod", "dev"]  # prod still attempted
    (row,) = await audit_rows(db)
    assert list(row["detail"]["failed_connections"]) == ["dev"]

    assert list(await svc.delete_group(INITIAL, "g1")) == ["dev"]
    assert await count(db, "groups") == 0


# --- admins ------------------------------------------------------------------------------


async def test_ordinary_admin_cannot_remove_admin(svc: RuleService, store: MemoryStore) -> None:
    await svc.add_admin(INITIAL, ORDINARY.id)
    await svc.add_admin(ORDINARY, 4)  # ordinary admins may add
    with pytest.raises(AdminForbidden):
        await svc.remove_admin(ORDINARY, 4)
    assert await store.check(ids.user(4), "admin", ids.GATEWAY_MAIN)


async def test_non_admin_cannot_add_admin(svc: RuleService) -> None:
    with pytest.raises(AdminForbidden):
        await svc.add_admin(PLAIN, 4)


async def test_initial_admin_removes_admin_but_never_an_initial_one(
    svc: RuleService, store: MemoryStore
) -> None:
    await svc.add_admin(INITIAL, ORDINARY.id)
    assert admin_tuple(ORDINARY.id) in await store.read(ids.GATEWAY_MAIN, "admin")
    await svc.remove_admin(INITIAL, ORDINARY.id)
    assert await store.read(ids.GATEWAY_MAIN, "admin") == []
    with pytest.raises(AdminForbidden):
        await svc.remove_admin(INITIAL, INITIAL.id)
    with pytest.raises(NotFound):
        await svc.remove_admin(INITIAL, 999)


# --- audit -------------------------------------------------------------------------------


async def test_every_mutating_method_writes_one_admin_audit_row(
    svc: RuleService, db: aiosqlite.Connection
) -> None:
    steps = [
        svc.create_group(INITIAL, "g1", None),
        svc.add_member(INITIAL, "g1", 4),
        svc.grant_schema_reader(INITIAL, "g1", "prod", "public"),
        svc.revoke_schema_reader(INITIAL, "g1", "prod", "public"),
        svc.grant_table_reader(INITIAL, "g1", "prod", "public", "t"),
        svc.revoke_table_reader(INITIAL, "g1", "prod", "public", "t"),
        svc.declare_row_policy(INITIAL, "prod", "public", "t", "team"),
        svc.grant_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a"),
        svc.revoke_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a"),
        svc.undeclare_row_policy(INITIAL, "prod", "public", "t"),
        svc.remove_member(INITIAL, "g1", 4),
        svc.add_admin(INITIAL, 4),
        svc.remove_admin(INITIAL, 4),
        svc.delete_group(INITIAL, "g1"),
    ]
    expected = [
        "create_group",
        "add_member",
        "grant_schema_reader",
        "revoke_schema_reader",
        "grant_table_reader",
        "revoke_table_reader",
        "declare_row_policy",
        "grant_row_set",
        "revoke_row_set",
        "undeclare_row_policy",
        "remove_member",
        "add_admin",
        "remove_admin",
        "delete_group",
    ]
    for done, step in enumerate(steps, start=1):
        await step
        assert await count(db, "audit_log") == done
    rows = await audit_rows(db)
    assert [r["detail"]["action"] for r in rows] == expected
    assert {r["kind"] for r in rows} == {"admin"}
    assert {r["user_id"] for r in rows} == {INITIAL.id}
    grant = rows[2]
    assert grant["connection_id"] is not None
    assert grant["detail"]["connection"] == "prod"
    assert grant["detail"]["written"] == [
        {"user": "group:g1#member", "relation": "reader", "object": "db_schema:prod/public"}
    ]
    assert rows[3]["detail"]["deleted"][0]["object"] == "db_schema:prod/public"
    assert rows[7]["detail"]["written"][1]["relation"] == "table"


async def test_rejected_calls_write_no_audit_row(
    svc: RuleService, db: aiosqlite.Connection
) -> None:
    await make_group(svc)
    before = await count(db, "audit_log")
    with pytest.raises(ValueError):
        await svc.grant_schema_reader(INITIAL, "g1", "prod", "*")
    with pytest.raises(NotFound):
        await svc.grant_schema_reader(INITIAL, "nope", "prod", "public")
    with pytest.raises(RuleConflict):
        await svc.grant_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
    assert await count(db, "audit_log") == before


# --- concurrency -------------------------------------------------------------------------


async def test_concurrent_schema_and_table_grants_allow_exactly_one(
    svc: RuleService, store: MemoryStore
) -> None:
    await make_group(svc)
    results = await asyncio.gather(
        svc.grant_schema_reader(INITIAL, "g1", "prod", "public"),
        svc.grant_table_reader(INITIAL, "g1", "prod", "public", "t"),
        return_exceptions=True,
    )
    conflicts = [r for r in results if isinstance(r, RuleConflict)]
    assert len(conflicts) == 1
    assert sum(r is None for r in results) == 1
    readers = [t for t in await store.read() if t.relation == "reader"]
    assert len(readers) == 1


@pytest.mark.parametrize("inline_result", [None, False, True])
@pytest.mark.parametrize("kind", ["member", "schema", "table", "row_set"])
async def test_revoke_returns_inline_status_after_store_write_under_global_lock(
    db: aiosqlite.Connection,
    store: MemoryStore,
    executor: FakeExecutor,
    stats: FakeStats,
    inline_result: bool | None,
    kind: str,
) -> None:
    calls: list[tuple[list[Tuple], float]] = []

    class Inline:
        async def apply_inline(self, deletes: Sequence[Tuple], timeout_s: float) -> bool:
            assert service._lock.locked()
            remaining = await store.read()
            assert all(item not in remaining for item in deletes)
            calls.append((list(deletes), timeout_s))
            return bool(inline_result)

    service = RuleService(
        db,
        store,
        executor,
        stats,
        inline=None if inline_result is None else Inline(),
        revoke_timeout_s=1.25,
    )
    await make_group(service)
    if kind == "member":
        await service.add_member(INITIAL, "g1", 4)
        result = await service.remove_member(INITIAL, "g1", 4)
        deleted = [Tuple(ids.user(4), "member", ids.group("g1"))]
    elif kind == "schema":
        await service.grant_schema_reader(INITIAL, "g1", "prod", "public")
        result = await service.revoke_schema_reader(INITIAL, "g1", "prod", "public")
        deleted = [Tuple(ids.group_member("g1"), "reader", ids.db_schema("prod", "public"))]
    elif kind == "table":
        await service.grant_table_reader(INITIAL, "g1", "prod", "public", "t")
        result = await service.revoke_table_reader(INITIAL, "g1", "prod", "public", "t")
        deleted = [Tuple(ids.group_member("g1"), "reader", ids.db_table("prod", "public", "t"))]
    else:
        await service.declare_row_policy(INITIAL, "prod", "public", "t", "team")
        await service.grant_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
        result = await service.revoke_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
        set_id = ids.row_set("prod", "public", "t", "team", "a")
        deleted = [
            Tuple(ids.group_member("g1"), "reader", set_id),
            Tuple(ids.db_table("prod", "public", "t"), "table", set_id),
        ]
    assert result == ("synced" if inline_result else "pending")
    assert calls == ([] if inline_result is None else [(deleted, 1.25)])
    assert (await audit_rows(db))[-1]["detail"]["deleted"] == [
        {"user": item.user, "relation": item.relation, "object": item.object} for item in deleted
    ]


async def test_delete_group_revokes_members_inline_and_preserves_failure_dictionary(
    db: aiosqlite.Connection, store: MemoryStore, executor: FakeExecutor, stats: FakeStats
) -> None:
    calls: list[list[Tuple]] = []

    class Inline:
        async def apply_inline(self, deletes: Sequence[Tuple], timeout_s: float) -> bool:
            assert service._lock.locked()
            assert await store.read(ids.group("g1"), "member") == []
            calls.append(list(deletes))
            return True

    service = RuleService(db, store, executor, stats, inline=Inline())
    await make_group(service)
    await service.add_member(INITIAL, "g1", 4)
    executor.fail_on.add("dev")
    failed = await service.delete_group(INITIAL, "g1")
    assert list(failed) == ["dev"]
    assert calls == [[Tuple(ids.user(4), "member", ids.group("g1"))]]
    rows = await audit_rows(db)
    deletion = [row for row in rows if row["detail"]["action"] == "delete_group"]
    assert [row["kind"] for row in deletion] == ["admin", "sync"]
    assert deletion[0]["detail"]["deleted"] == [
        {"user": ids.user(4), "relation": "member", "object": ids.group("g1")}
    ]
    assert deletion[1]["detail"]["failed_connections"] == failed


async def test_inline_not_called_when_store_delete_fails(
    db: aiosqlite.Connection, executor: FakeExecutor, stats: FakeStats
) -> None:
    class Store(MemoryStore):
        async def write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
            if deletes:
                raise PermissionStoreUnavailable("offline")
            await super().write(writes, deletes)

    class Inline:
        async def apply_inline(self, deletes: Sequence[Tuple], timeout_s: float) -> bool:
            pytest.fail("inline revoke ran before a successful store write")

    service = RuleService(db, Store(), executor, stats, inline=Inline())
    await make_group(service)
    with pytest.raises(PermissionStoreUnavailable):
        await service.remove_member(INITIAL, "g1", 4)


@pytest.mark.parametrize("kind", ["member", "schema", "table", "row_set", "group"])
async def test_admin_audit_survives_cancellation_during_inline_revoke(
    db: aiosqlite.Connection,
    store: MemoryStore,
    executor: FakeExecutor,
    stats: FakeStats,
    kind: str,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    class Inline:
        async def apply_inline(self, deletes: Sequence[Tuple], timeout_s: float) -> bool:
            entered.set()
            await release.wait()
            return True

    service = RuleService(db, store, executor, stats, inline=Inline())
    await make_group(service)
    if kind in {"member", "group"}:
        await service.add_member(INITIAL, "g1", 4)
        call = (
            service.remove_member(INITIAL, "g1", 4)
            if kind == "member"
            else service.delete_group(INITIAL, "g1")
        )
        action = "remove_member" if kind == "member" else "delete_group"
    elif kind == "schema":
        await service.grant_schema_reader(INITIAL, "g1", "prod", "public")
        call = service.revoke_schema_reader(INITIAL, "g1", "prod", "public")
        action = "revoke_schema_reader"
    elif kind == "table":
        await service.grant_table_reader(INITIAL, "g1", "prod", "public", "t")
        call = service.revoke_table_reader(INITIAL, "g1", "prod", "public", "t")
        action = "revoke_table_reader"
    else:
        await service.declare_row_policy(INITIAL, "prod", "public", "t", "team")
        await service.grant_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
        call = service.revoke_row_set(INITIAL, "g1", "prod", "public", "t", "team", "a")
        action = "revoke_row_set"
    task = asyncio.create_task(call)
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    rows = await audit_rows(db)
    assert rows[-1]["kind"] == "admin"
    assert rows[-1]["detail"]["action"] == action
    assert rows[-1]["detail"]["deleted"]
    for item in rows[-1]["detail"]["deleted"]:
        assert Tuple(**item) not in await store.read(item["object"])
    if kind == "group":
        # The group row goes with the audit row, before the inline wait.
        assert await count(db, "groups") == 0


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("dropping", [False, True])
async def test_group_role_apply_holds_global_then_connection_lock(
    db: aiosqlite.Connection,
    store: MemoryStore,
    executor: FakeExecutor,
    stats: FakeStats,
    monkeypatch: pytest.MonkeyPatch,
    shared: bool,
    dropping: bool,
) -> None:
    queued = asyncio.Event()
    locks = ConnectionLocks()
    service = RuleService(db, store, executor, stats, locks=locks if shared else None)
    if not shared:
        locks = service._locks
    if dropping:
        await make_group(service)
    executor.calls.clear()

    class ObservedLock(asyncio.Lock):
        async def acquire(self) -> Literal[True]:
            if self.locked():
                queued.set()
            return await super().acquire()

    locks._locks["prod"] = ObservedLock()
    apply = executor.apply

    async def observe(connection: str, ops: Sequence[PgOp]) -> Sequence[PgOp]:
        assert service._lock.locked()
        assert locks(connection).locked()
        return await apply(connection, ops)

    monkeypatch.setattr(executor, "apply", observe)
    async with locks("prod"):
        task = asyncio.create_task(
            service.delete_group(INITIAL, "g1") if dropping else service.create_group(INITIAL, "g1")
        )
        await asyncio.wait_for(queued.wait(), 2)
        assert executor.calls == []
    assert await asyncio.wait_for(task, 2) == {}
    assert [name for name, _ in executor.calls] == ["prod", "dev"]
