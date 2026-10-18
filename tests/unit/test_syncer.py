"""Checkpoint, recovery, isolation and transaction lifetime tests for the Syncer."""

import asyncio
import json
from collections.abc import AsyncIterator, Sequence
from typing import Literal
from unittest.mock import AsyncMock

import aiosqlite
import pytest

from db_gateway import metadata
from db_gateway.permissions import ids
from db_gateway.permissions.context import ConnectionLocks
from db_gateway.permissions.executor import ApplyError, TransientApplyError
from db_gateway.permissions.store import ChangesPage, PermissionStoreUnavailable, Tuple
from db_gateway.permissions.store_memory import MemoryStore
from db_gateway.permissions.syncer import Syncer
from db_gateway.permissions.types import (
    CreateGroupRole,
    DropGroupRole,
    GrantMembership,
    PgOp,
    RevokeMembership,
)

MEMBER = Tuple("user:1", "member", "group:team")
TABLE = Tuple("group:team#member", "reader", "db_table:prod/public/items")


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[PgOp]]] = []
        self.errors: dict[str, Exception] = {}
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.block: set[str] = set()
        self.active: set[str] = set()

    async def apply(self, connection: str, ops: Sequence[PgOp]) -> Sequence[PgOp]:
        assert connection not in self.active, "concurrent application on one connection"
        self.active.add(connection)
        try:
            self.calls.append((connection, list(ops)))
            self.entered.set()
            if connection in self.block:
                await self.release.wait()
            if connection in self.errors:
                raise self.errors[connection]
            return []
        finally:
            self.active.remove(connection)


@pytest.fixture
async def db() -> AsyncIterator[aiosqlite.Connection]:
    conn = await metadata.connect(":memory:")
    try:
        await metadata.migrate(conn)
        async with metadata.transaction(conn):
            await conn.execute(
                "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
                "VALUES ('prod', 'h', 'd', 'ref')"
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
def reconcile() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def syncer(
    db: aiosqlite.Connection,
    store: MemoryStore,
    executor: FakeExecutor,
    reconcile: AsyncMock,
) -> Syncer:
    return Syncer(
        db,
        store,
        executor,
        ConnectionLocks(),
        fga_store_id="store",
        poll_interval_s=2,
        full_reconcile=reconcile,
    )


async def test_token_advances_only_after_whole_page_succeeds(
    syncer: Syncer, store: MemoryStore, executor: FakeExecutor
) -> None:
    await store.write([MEMBER, TABLE])
    executor.block.add("prod")
    task = asyncio.create_task(syncer.sync_once("prod"))
    try:
        await asyncio.wait_for(executor.entered.wait(), 2)
        assert (await syncer.status())[0]["continuation_token"] is None
    finally:
        executor.release.set()
        await asyncio.wait_for(task, 2)
    state = (await syncer.status())[0]
    assert state["continuation_token"] == "2"
    assert state["last_applied_at"] is not None
    assert state["fail_count"] == 0
    assert executor.calls[0] == ("prod", [GrantMembership("g_team", "u_1")])


async def test_group_creation_precedes_membership_in_change_stream(
    syncer: Syncer, store: MemoryStore, executor: FakeExecutor
) -> None:
    await store.write([ids.group_tuple("team")])
    await store.write([MEMBER])
    await syncer.sync_once("prod")
    assert executor.calls == [
        ("prod", [CreateGroupRole("g_team")]),
        ("prod", [GrantMembership("g_team", "u_1")]),
    ]


async def test_inline_group_drop_dependency_is_pending_and_stream_retries(
    syncer: Syncer, store: MemoryStore, executor: FakeExecutor, monkeypatch: pytest.MonkeyPatch
) -> None:
    group = ids.group_tuple("team")
    await store.write([group, MEMBER])
    await syncer.sync_once("prod")
    token = (await syncer.status())[0]["continuation_token"]
    deleted = [MEMBER, group]
    await store.write(deletes=deleted)
    executor.calls.clear()
    apply = executor.apply
    blocked = True

    async def fail_drop(connection: str, ops: Sequence[PgOp]) -> Sequence[PgOp]:
        assert syncer._locks(connection).locked()
        skipped = await apply(connection, ops)
        if blocked and DropGroupRole("g_team") in ops:
            raise TransientApplyError(
                connection, DropGroupRole("g_team"), RuntimeError("dependent objects still exist")
            )
        return skipped

    monkeypatch.setattr(executor, "apply", fail_drop)
    assert await syncer.apply_inline(deleted, 2) is False
    assert executor.calls == [
        ("prod", [RevokeMembership("g_team", "u_1")]),
        ("prod", [DropGroupRole("g_team")]),
    ]
    await syncer.sync_once("prod")
    status = (await syncer.status())[0]
    assert status["continuation_token"] == token
    assert status["fail_count"] == 1
    blocked = False
    await syncer.sync_once("prod")
    status = (await syncer.status())[0]
    assert status["continuation_token"] == "4"
    assert status["last_error"] is None
    assert status["fail_count"] == 0
    assert executor.calls[-1] == ("prod", [DropGroupRole("g_team")])


async def test_failure_in_later_page_keeps_last_successful_page_token(
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await store.write([Tuple(f"user:{n}", "member", "group:team") for n in range(1, 101)])
    await store.write([Tuple("user:101", "member", "group:team")])
    apply = executor.apply

    async def fail_last(connection: str, ops: Sequence[PgOp]) -> Sequence[PgOp]:
        if ops == [GrantMembership("g_team", "u_101")]:
            raise RuntimeError("last page failed")
        return await apply(connection, ops)

    monkeypatch.setattr(executor, "apply", fail_last)
    await syncer.sync_once("prod")
    state = (await syncer.status())[0]
    assert state["continuation_token"] == "100"
    assert state["fail_count"] == 1
    monkeypatch.setattr(executor, "apply", apply)
    await syncer.sync_once("prod")
    assert len(executor.calls) == 101
    assert (await syncer.status())[0]["continuation_token"] == "101"


@pytest.mark.parametrize("error_type", [RuntimeError, ApplyError, TransientApplyError])
async def test_failure_preserves_checkpoint_and_success_clears_error(
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    error_type: type[Exception],
) -> None:
    await store.write([MEMBER])
    await syncer.sync_once("prod")
    await store.write([TABLE])
    executor.errors["prod"] = (
        ApplyError("prod", None, RuntimeError("broken"))
        if error_type is ApplyError
        else TransientApplyError("prod", None, RuntimeError("broken"))
        if error_type is TransientApplyError
        else RuntimeError("broken")
    )
    for n in (1, 2):
        await syncer.sync_once("prod")
        state = (await syncer.status())[0]
        assert state["continuation_token"] == "1"
        assert state["fail_count"] == n
        assert "broken" in (state["last_error"] or "")
    executor.errors.clear()
    await syncer.sync_once("prod")
    assert (await syncer.status())[0]["continuation_token"] == "2"
    assert (await syncer.status())[0]["last_error"] is None
    assert (await syncer.status())[0]["fail_count"] == 0


async def test_backoff_is_used_and_capped(
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await store.write([MEMBER])
    executor.errors["prod"] = RuntimeError("offline")
    delays: list[float] = []

    async def pause(delay: float) -> None:
        delays.append(delay)
        if len(delays) == 6:
            syncer._stopping.set()

    monkeypatch.setattr(syncer, "_pause", pause)
    await syncer._consume("prod")
    assert delays == [4, 8, 16, 32, 60, 60]
    assert (await syncer.status())[0]["fail_count"] == 6


async def test_poison_tuple_is_audited_and_does_not_block(
    db: aiosqlite.Connection, syncer: Syncer, store: MemoryStore, executor: FakeExecutor
) -> None:
    poison = Tuple("group:team#member", "reader", "db_table:removed/public/items")
    await store.write([poison, MEMBER])
    await syncer.sync_once("prod")
    assert (await syncer.status())[0]["continuation_token"] == "2"
    assert executor.calls == [("prod", [GrantMembership("g_team", "u_1")])]
    async with db.execute("SELECT kind, error, detail FROM audit_log") as cursor:
        (row,) = await cursor.fetchall()
    assert row[0] == "sync"
    assert "not configured" in row[1]
    assert json.loads(row[2])["tuple"]["object"] == poison.object


async def test_background_consumers_progress_independently(
    db: aiosqlite.Connection,
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with metadata.transaction(db):
        await db.execute(
            "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
            "VALUES ('dev', 'h', 'd', 'ref')"
        )
    await store.write([MEMBER])
    executor.block.add("prod")
    executor.errors["prod"] = RuntimeError("offline")
    dev_done = asyncio.Event()
    checkpoint = syncer._checkpoint

    async def observe(connection: str, token: str) -> None:
        await checkpoint(connection, token)
        if connection == "dev" and token == "1":
            dev_done.set()

    monkeypatch.setattr(syncer, "_checkpoint", observe)
    task = asyncio.create_task(syncer.run())
    try:
        await asyncio.wait_for(dev_done.wait(), 2)
        states = {s["connection"]: s for s in await syncer.status()}
        assert states["prod"]["continuation_token"] is None
        assert states["dev"]["continuation_token"] == "1"
    finally:
        executor.release.set()
        await syncer.stop()
        await asyncio.wait_for(task, 2)
    assert (await syncer.status())[0]["fail_count"] == 1


async def test_invalid_token_scans_without_apply_before_reconcile(
    db: aiosqlite.Connection,
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    reconcile: AsyncMock,
) -> None:
    # More than one page must be scanned to capture the latest position.
    for start in (1, 101):
        await store.write(
            [Tuple(f"user:{n}", "member", "group:team") for n in range(start, start + 100)]
        )
    await syncer.status()
    async with metadata.transaction(db):
        await db.execute(
            "UPDATE sync_state SET continuation_token = 'expired' WHERE consumer = 'pg:prod'"
        )

    async def full_reconcile(connection: str) -> None:
        assert connection == "prod"
        assert executor.calls == []
        # A normal reconciler acquires the same lock; recovery must not deadlock.
        async with syncer._locks(connection):
            await store.write(deletes=[MEMBER])

    reconcile.side_effect = full_reconcile
    await asyncio.wait_for(syncer.sync_once("prod"), 2)
    reconcile.assert_awaited_once_with("prod")
    assert (await syncer.status())[0]["continuation_token"] == "200"
    assert executor.calls == []
    await syncer.sync_once("prod")
    assert executor.calls == [("prod", [RevokeMembership("g_team", "u_1")])]
    assert (await syncer.status())[0]["continuation_token"] == "201"


async def test_reconcile_failure_keeps_invalid_token_for_retry(
    db: aiosqlite.Connection, syncer: Syncer, reconcile: AsyncMock
) -> None:
    await syncer.status()
    async with metadata.transaction(db):
        await db.execute("UPDATE sync_state SET continuation_token = 'expired'")
    reconcile.side_effect = RuntimeError("reconcile failed")
    await syncer.sync_once("prod")
    state = (await syncer.status())[0]
    assert state["continuation_token"] == "expired"
    assert state["fail_count"] == 1
    assert "reconcile failed" in (state["last_error"] or "")


async def test_store_change_resets_token_and_status(
    db: aiosqlite.Connection,
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    reconcile: AsyncMock,
) -> None:
    await store.write([MEMBER])
    await syncer.sync_once("prod")
    async with metadata.transaction(db):
        await db.execute(
            "UPDATE sync_state SET fga_store_id = 'old', continuation_token = '999', "
            "last_error = 'old failure', fail_count = 9"
        )
    executor.calls.clear()
    await syncer.sync_once("prod")
    assert executor.calls == []
    reconcile.assert_awaited_once_with("prod")
    assert (await syncer.status())[0]["continuation_token"] == "1"
    assert (await syncer.status())[0]["fail_count"] == 0


async def test_store_reset_failure_preserves_identity_until_reconcile_succeeds(
    db: aiosqlite.Connection,
    syncer: Syncer,
    store: MemoryStore,
    reconcile: AsyncMock,
) -> None:
    await store.write([MEMBER])
    await syncer.status()
    async with metadata.transaction(db):
        await db.execute("UPDATE sync_state SET fga_store_id = 'old', continuation_token = '999'")
    reconcile.side_effect = RuntimeError("reset failed")
    for failures in (1, 2):
        await syncer.sync_once("prod")
        state = (await syncer.status())[0]
        assert state["continuation_token"] == "999"
        assert state["fail_count"] == failures
        assert "reset failed" in (state["last_error"] or "")
        async with db.execute("SELECT fga_store_id FROM sync_state") as cursor:
            assert await cursor.fetchone() == ("old",)
    reconcile.side_effect = None
    await syncer.sync_once("prod")
    assert reconcile.await_count == 3
    assert (await syncer.status())[0]["continuation_token"] == "1"
    async with db.execute("SELECT fga_store_id FROM sync_state") as cursor:
        assert await cursor.fetchone() == ("store",)


async def test_unavailable_store_keeps_existing_state(
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await store.write([MEMBER])
    await syncer.sync_once("prod")
    executor.calls.clear()

    async def unavailable(token: str | None, page_size: int = 100) -> ChangesPage:
        raise PermissionStoreUnavailable("OpenFGA offline")

    monkeypatch.setattr(store, "read_changes", unavailable)
    await syncer.sync_once("prod")
    state = (await syncer.status())[0]
    assert state["continuation_token"] == "1"
    assert state["fail_count"] == 1
    assert "OpenFGA offline" in (state["last_error"] or "")
    assert executor.calls == []


async def test_membership_grantor_error_requires_operator_and_keeps_retrying(
    syncer: Syncer, store: MemoryStore, executor: FakeExecutor
) -> None:
    await store.write([MEMBER])
    await syncer.sync_once("prod")
    await store.write(deletes=[MEMBER])
    executor.errors["prod"] = ApplyError(
        "prod",
        RevokeMembership("g_team", "u_1"),
        RuntimeError('permission denied to revoke privileges granted by role "postgres"'),
    )
    await syncer.sync_once("prod")
    await syncer.sync_once("prod")
    state = (await syncer.status())[0]
    assert state["continuation_token"] == "1"
    assert state["fail_count"] == 2
    assert "operator must revoke this membership with a superuser" in (state["last_error"] or "")


async def test_inline_timeout_keeps_transaction_alive(
    syncer: Syncer, executor: FakeExecutor
) -> None:
    executor.block.add("prod")
    task = asyncio.create_task(syncer.apply_inline([MEMBER], 0))
    assert await asyncio.wait_for(task, 2) is False
    await asyncio.wait_for(executor.entered.wait(), 2)
    assert executor.active == {"prod"}
    stopping = asyncio.create_task(syncer.stop())
    await asyncio.wait_for(syncer._stopping.wait(), 2)
    assert not stopping.done()
    executor.release.set()
    await asyncio.wait_for(stopping, 2)
    assert not executor.active
    assert executor.calls == [("prod", [RevokeMembership("g_team", "u_1")])]


@pytest.mark.parametrize("inline_first", [False, True])
async def test_inline_and_stream_share_connection_lock(
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    inline_first: bool,
) -> None:
    contended = asyncio.Event()

    class ObservedLock(asyncio.Lock):
        async def acquire(self) -> Literal[True]:
            if self.locked():
                contended.set()
            return await super().acquire()

    syncer._locks._locks["prod"] = ObservedLock()
    if not inline_first:
        await store.write([MEMBER])
    executor.block.add("prod")
    first = asyncio.create_task(
        syncer.apply_inline([MEMBER], 10) if inline_first else syncer.sync_once("prod")
    )
    await asyncio.wait_for(executor.entered.wait(), 2)
    await store.write(deletes=[MEMBER])
    second = asyncio.create_task(
        syncer.sync_once("prod") if inline_first else syncer.apply_inline([MEMBER], 10)
    )
    try:
        await asyncio.wait_for(contended.wait(), 2)
        assert len(executor.calls) == 1
    finally:
        executor.release.set()
        await asyncio.wait_for(asyncio.gather(first, second), 2)
    assert len(executor.calls) == (1 if inline_first else 3)
    expected = (
        [RevokeMembership]
        if inline_first
        else [
            GrantMembership,
            RevokeMembership,
            RevokeMembership,
        ]
    )
    assert [type(ops[0]) for _, ops in executor.calls] == expected


async def test_inline_failure_still_attempts_other_connections(
    db: aiosqlite.Connection, syncer: Syncer, executor: FakeExecutor
) -> None:
    async with metadata.transaction(db):
        await db.execute(
            "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
            "VALUES ('dev', 'h', 'd', 'ref')"
        )
    executor.errors["prod"] = RuntimeError("offline")
    assert await syncer.apply_inline([MEMBER], 2) is False
    assert [connection for connection, _ in executor.calls] == ["dev", "prod"]


async def test_inline_mapping_failure_is_pending(db: aiosqlite.Connection, syncer: Syncer) -> None:
    before = await syncer.status()
    assert (
        await syncer.apply_inline(
            [Tuple("group:team#member", "reader", "db_table:removed/public/t")], 2
        )
        is False
    )
    assert await syncer.status() == before
    async with db.execute("SELECT detail, error FROM audit_log") as cursor:
        (row,) = await cursor.fetchall()
    assert json.loads(row[0])["source"] == "inline"
    assert "not configured" in row[1]


async def test_connections_are_reloaded_and_removed_connections_are_ignored(
    db: aiosqlite.Connection, syncer: Syncer, store: MemoryStore, executor: FakeExecutor
) -> None:
    await store.write([MEMBER])
    await syncer.sync_once("prod")
    async with metadata.transaction(db):
        await db.execute(
            "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
            "VALUES ('dev', 'h', 'd', 'ref')"
        )
        await db.execute("DELETE FROM connections WHERE name = 'prod'")
    executor.calls.clear()
    await syncer.sync_once("prod")
    await syncer.sync_once("dev")
    assert executor.calls == [("dev", [GrantMembership("g_team", "u_1")])]
    assert [state["connection"] for state in await syncer.status()] == ["dev"]


async def test_running_syncer_discovers_new_connections(
    db: aiosqlite.Connection,
    syncer: Syncer,
    store: MemoryStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await store.write([MEMBER])
    discovered = {"prod": asyncio.Event(), "dev": asyncio.Event()}
    manager_step = asyncio.Event()
    checkpoint = syncer._checkpoint
    pause = syncer._pause

    async def observe(connection: str, token: str) -> None:
        await checkpoint(connection, token)
        discovered[connection].set()

    async def stepped_pause(delay: float) -> None:
        task = asyncio.current_task()
        assert task is not None
        if task.get_name() == "manager":
            await manager_step.wait()
            manager_step.clear()
        else:
            await pause(delay)

    monkeypatch.setattr(syncer, "_checkpoint", observe)
    monkeypatch.setattr(syncer, "_pause", stepped_pause)
    running = asyncio.create_task(syncer.run(), name="manager")
    try:
        await asyncio.wait_for(discovered["prod"].wait(), 2)
        async with metadata.transaction(db):
            await db.execute(
                "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
                "VALUES ('dev', 'h', 'd', 'ref')"
            )
        manager_step.set()
        await asyncio.wait_for(discovered["dev"].wait(), 2)
        assert set(syncer._workers) == {"prod", "dev"}
        assert all(state["continuation_token"] == "1" for state in await syncer.status())
    finally:
        await syncer.stop()
        manager_step.set()
        await asyncio.wait_for(running, 2)


async def test_page_read_is_locked_before_inline_can_revoke(
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page_read, release_page, inline_queued = asyncio.Event(), asyncio.Event(), asyncio.Event()
    read_changes = store.read_changes
    stream: asyncio.Task[None] | None = None

    class ObservedLock(asyncio.Lock):
        async def acquire(self) -> Literal[True]:
            if asyncio.current_task() is not stream:
                inline_queued.set()
            return await super().acquire()

    async def paused_read(token: str | None, page_size: int = 100) -> ChangesPage:
        if token is not None:
            raise PermissionStoreUnavailable("second page offline")
        page = await read_changes(token, page_size)
        page_read.set()
        await release_page.wait()
        return page

    syncer._locks._locks["prod"] = ObservedLock()
    monkeypatch.setattr(store, "read_changes", paused_read)
    await store.write([MEMBER])
    stream = asyncio.create_task(syncer.sync_once("prod"))
    async with asyncio.timeout(2):
        await page_read.wait()
        await store.write(deletes=[MEMBER])
        inline = asyncio.create_task(syncer.apply_inline([MEMBER], 10))
        try:
            await inline_queued.wait()
        finally:
            release_page.set()
        await stream
        assert await inline is True
    assert await store.read(MEMBER.object) == []
    assert [type(ops[0]) for _, ops in executor.calls] == [GrantMembership, RevokeMembership]


async def test_inline_queues_every_connection_before_timeout(
    db: aiosqlite.Connection,
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
) -> None:
    async with metadata.transaction(db):
        await db.execute(
            "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
            "VALUES ('dev', 'h', 'd', 'ref')"
        )
    queued = asyncio.Event()

    class ObservedLock(asyncio.Lock):
        async def acquire(self) -> Literal[True]:
            if self.locked():
                queued.set()
            return await super().acquire()

    syncer._locks._locks["prod"] = ObservedLock()
    executor.block.add("dev")  # Membership mapping visits dev before prod.
    async with syncer._locks("prod"):
        assert await syncer.apply_inline([MEMBER], 0) is False
        await asyncio.wait_for(executor.entered.wait(), 2)
        assert queued.is_set()
        await store.write([MEMBER])
        stream = asyncio.create_task(syncer.sync_once("prod"))
    try:
        await asyncio.wait_for(stream, 2)
        assert executor.calls[-1] == ("prod", [GrantMembership("g_team", "u_1")])
    finally:
        executor.release.set()
        await asyncio.wait_for(syncer.stop(), 2)
    assert executor.calls[-1] == ("prod", [GrantMembership("g_team", "u_1")])


async def test_inline_rechecks_each_tuple_after_taking_connection_lock(
    syncer: Syncer, store: MemoryStore, executor: FakeExecutor
) -> None:
    async with syncer._locks("prod"):
        assert await syncer.apply_inline([MEMBER, TABLE], 0) is False
        await store.write([MEMBER])
    await asyncio.wait_for(syncer.stop(), 2)
    assert len(executor.calls) == 1
    assert all(not isinstance(op, RevokeMembership) for _, ops in executor.calls for op in ops)
    assert await store.read(MEMBER.object) == [MEMBER]


async def test_inline_store_read_failure_still_revokes_and_audits_without_backoff(
    db: aiosqlite.Connection,
    syncer: Syncer,
    store: MemoryStore,
    executor: FakeExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = await syncer.status()
    monkeypatch.setattr(store, "read", AsyncMock(side_effect=PermissionStoreUnavailable("offline")))
    assert await syncer.apply_inline([MEMBER], 2) is True
    assert executor.calls == [("prod", [RevokeMembership("g_team", "u_1")])]
    assert await syncer.status() == before
    async with db.execute("SELECT detail, error FROM audit_log") as cursor:
        (row,) = await cursor.fetchall()
    assert json.loads(row[0])["source"] == "inline"
    assert "offline" in row[1]


async def test_inline_apply_failure_does_not_change_stream_status(
    db: aiosqlite.Connection, syncer: Syncer, executor: FakeExecutor
) -> None:
    before = await syncer.status()
    executor.errors["prod"] = RuntimeError("inline failed")
    assert await syncer.apply_inline([MEMBER], 2) is False
    assert await syncer.status() == before
    async with db.execute("SELECT detail, error FROM audit_log") as cursor:
        (row,) = await cursor.fetchall()
    assert json.loads(row[0])["source"] == "inline"
    assert "inline failed" in row[1]


async def test_poison_audit_waits_for_successful_page_checkpoint(
    db: aiosqlite.Connection, syncer: Syncer, store: MemoryStore, executor: FakeExecutor
) -> None:
    poison = Tuple("group:team#member", "reader", "db_table:removed/public/items")
    await store.write([poison, MEMBER])
    executor.errors["prod"] = RuntimeError("later op failed")
    for _ in range(2):
        await syncer.sync_once("prod")
    async with db.execute("SELECT detail FROM audit_log") as cursor:
        assert all("tuple" not in json.loads(row[0]) for row in await cursor.fetchall())
    executor.errors.clear()
    await syncer.sync_once("prod")
    await syncer.sync_once("prod")
    async with db.execute("SELECT detail FROM audit_log") as cursor:
        poisoned = [json.loads(row[0]) for row in await cursor.fetchall() if "tuple" in row[0]]
    assert len(poisoned) == 1


async def test_idle_page_does_not_checkpoint_or_change_last_applied_time(
    syncer: Syncer, store: MemoryStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await store.write([MEMBER])
    await syncer.sync_once("prod")
    before = await syncer.status()
    checkpoint = AsyncMock(wraps=syncer._checkpoint)
    monkeypatch.setattr(syncer, "_checkpoint", checkpoint)
    await syncer.sync_once("prod")
    checkpoint.assert_not_awaited()
    assert await syncer.status() == before


async def test_empty_stream_does_not_write_an_initial_checkpoint(
    syncer: Syncer, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint = AsyncMock(wraps=syncer._checkpoint)
    monkeypatch.setattr(syncer, "_checkpoint", checkpoint)
    await syncer.sync_once("prod")
    checkpoint.assert_not_awaited()
    assert (await syncer.status())[0]["last_applied_at"] is None


async def test_healthy_idle_poll_clears_stream_error_without_checkpoint(
    syncer: Syncer, store: MemoryStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await store.write([MEMBER])
    await syncer.sync_once("prod")
    applied_at = (await syncer.status())[0]["last_applied_at"]
    await syncer._error("prod", PermissionStoreUnavailable("offline"))
    checkpoint = AsyncMock(wraps=syncer._checkpoint)
    monkeypatch.setattr(syncer, "_checkpoint", checkpoint)
    await syncer.sync_once("prod")
    checkpoint.assert_not_awaited()
    state = (await syncer.status())[0]
    assert state["last_error"] is None
    assert state["fail_count"] == 0
    assert state["last_applied_at"] == applied_at


async def test_shutdown_stops_drain_after_current_page(
    syncer: Syncer, store: MemoryStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    for start in (1, 101):
        await store.write(
            [Tuple(f"user:{n}", "member", "group:team") for n in range(start, start + 100)]
        )
    checkpoint = syncer._checkpoint

    async def stop_after_page(connection: str, token: str) -> None:
        await checkpoint(connection, token)
        syncer._stopping.set()

    monkeypatch.setattr(syncer, "_checkpoint", stop_after_page)
    await syncer.sync_once("prod")
    assert (await syncer.status())[0]["continuation_token"] == "100"


async def test_manager_restarts_dead_consumer_after_backoff(
    syncer: Syncer, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    crashed, restarted = asyncio.Event(), asyncio.Event()
    attempts = 0
    delays: list[float] = []
    manager_steps: asyncio.Queue[None] = asyncio.Queue()

    async def consume(connection: str) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            crashed.set()
            manager_steps.put_nowait(None)
            raise RuntimeError("consumer crashed")
        restarted.set()
        syncer._stopping.set()
        manager_steps.put_nowait(None)

    async def pause(delay: float) -> None:
        delays.append(delay)
        task = asyncio.current_task()
        assert task is not None
        if task.get_name() == "manager":
            await manager_steps.get()

    monkeypatch.setattr(syncer, "_consume", consume)
    monkeypatch.setattr(syncer, "_pause", pause)
    await asyncio.wait_for(asyncio.create_task(syncer.run(), name="manager"), 2)
    assert attempts == 2
    assert syncer._backoff(1) in delays
    assert "consumer crashed" in caplog.text


async def test_stop_drains_other_tasks_when_one_worker_has_failed(
    syncer: Syncer, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    failed, release, entered = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def crash() -> None:
        failed.set()
        raise RuntimeError("dead worker")

    async def inflight() -> None:
        entered.set()
        await release.wait()

    syncer._workers = {"prod": asyncio.create_task(crash()), "dev": asyncio.create_task(inflight())}
    await asyncio.wait_for(asyncio.gather(failed.wait(), entered.wait()), 2)
    gather = asyncio.gather
    draining = asyncio.Event()

    def observed_gather(*tasks, **kwargs):
        result = gather(*tasks, **kwargs)
        draining.set()
        return result

    monkeypatch.setattr(asyncio, "gather", observed_gather)
    stopping = asyncio.create_task(syncer.stop())
    await asyncio.wait_for(draining.wait(), 2)
    try:
        assert not stopping.done()
    finally:
        release.set()
        await asyncio.wait_for(stopping, 2)
    assert all(task.done() for task in syncer._workers.values())
    assert "dead worker" in caplog.text
