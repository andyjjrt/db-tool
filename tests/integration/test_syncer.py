"""Change stream and inline revocation against real OpenFGA and a non-superuser PG admin."""

import secrets
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from unittest.mock import AsyncMock

import aiosqlite
import psycopg
import pytest
import pytest_asyncio
from psycopg.sql import SQL, Identifier, Literal

from db_gateway import metadata
from db_gateway.permissions import actual
from db_gateway.permissions.admin import AdminUser
from db_gateway.permissions.context import ConnectionLocks
from db_gateway.permissions.executor import PgExecutor
from db_gateway.permissions.rules import RuleService
from db_gateway.permissions.store import (
    ChangesPage,
    ContinuationTokenInvalid,
    PermissionStore,
    PermissionStoreUnavailable,
    Tuple,
)
from db_gateway.permissions.store_openfga import OpenFgaStore
from db_gateway.permissions.syncer import Syncer
from db_gateway.permissions.types import group_role, user_role
from tests.conftest import RoleInfo
from tests.integration.test_target_db import TargetAdmin
from tests.integration.test_target_db import target_admin as target_admin

pytestmark = pytest.mark.integration


@dataclass
class SyncTarget:
    db: aiosqlite.Connection
    store: OpenFgaStore
    syncer: Syncer
    rules: RuleService
    executor: PgExecutor
    admin: TargetAdmin
    actor: AdminUser
    user: RoleInfo
    group: str
    connect: Callable[[str], Awaitable[psycopg.AsyncConnection]]

    async def snapshot(self) -> actual.ActualState:
        async with await self.connect("target") as conn:
            return await actual.read_actual(
                conn,
                schemas=[self.admin.schema],
                default_privilege_owners=[self.admin.login.name],
            )


@pytest_asyncio.fixture
async def sync_target(
    cluster_lock: psycopg.AsyncConnection | None,
    target_admin: TargetAdmin,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    unique_name: Callable[[str], str],
    fga_store: str,
    openfga_url: str,
) -> AsyncIterator[SyncTarget]:
    async def connect(name: str) -> psycopg.AsyncConnection:
        assert name == "target"
        return await connect_as(target_admin.login)

    async def reconcile(connection: str) -> None:
        pytest.fail(f"fresh test stream unexpectedly required reconciliation: {connection}")

    db = await metadata.connect(":memory:")
    store = OpenFgaStore(openfga_url, fga_store)
    executor = PgExecutor(connect)
    syncer = Syncer(
        db,
        store,
        executor,
        ConnectionLocks(),
        fga_store_id=fga_store,
        poll_interval_s=2,
        full_reconcile=reconcile,
    )
    try:
        await metadata.migrate(db)
        await store.ensure_model()
        user_id = secrets.randbits(48)
        user = RoleInfo(user_role(user_id), "syncer-test-password")
        actor = AdminUser(user_id, user.name)
        async with metadata.transaction(db):
            await db.execute(
                "INSERT INTO users (id, login_key) VALUES (?, ?)", (user_id, user.name)
            )
            await db.execute(
                "INSERT INTO connections (name, host, dbname, admin_secret_ref, "
                "default_privilege_owners) VALUES ('target', 'h', 'd', 'ref', ?)",
                ('["' + target_admin.login.name + '"]',),
            )
        async with await connect("target") as conn:
            await conn.execute(
                SQL("CREATE ROLE {} LOGIN INHERIT PASSWORD {}").format(
                    Identifier(user.name), Literal(user.password)
                )
            )
            await conn.execute(
                SQL("GRANT gw_managed TO {} WITH INHERIT TRUE").format(Identifier(user.name))
            )
            for table in ("items", "other"):
                await conn.execute(
                    SQL("CREATE TABLE {} (value integer)").format(
                        Identifier(target_admin.schema, table)
                    )
                )
                await conn.execute(
                    SQL("INSERT INTO {} VALUES (42)").format(Identifier(target_admin.schema, table))
                )
        stats = AsyncMock()
        rules = RuleService(db, store, executor, stats, inline=syncer, locks=syncer._locks)
        group = unique_name("team")
        assert await rules.create_group(actor, group) == {}
        await rules.add_member(actor, group, user_id)
        yield SyncTarget(
            db, store, syncer, rules, executor, target_admin, actor, user, group, connect
        )
    finally:
        await syncer.stop()
        await store.aclose()
        await db.close()


@pytest.mark.parametrize("kind", ["table", "membership"])
async def test_table_grant_and_inline_revoke_are_visible_to_real_login(
    sync_target: SyncTarget,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    kind: str,
) -> None:
    target = sync_target
    schema = target.admin.schema
    await target.rules.grant_table_reader(target.actor, target.group, "target", schema, "items")
    await target.syncer.sync_once("target")
    assert (await target.syncer.status())[0]["last_error"] is None
    async with await connect_as(target.user) as user:
        query = SQL("SELECT value FROM {}").format(Identifier(schema, "items"))
        assert await (await user.execute(query)).fetchall() == [(42,)]
        result = (
            await target.rules.revoke_table_reader(
                target.actor, target.group, "target", schema, "items"
            )
            if kind == "table"
            else await target.rules.remove_member(target.actor, target.group, target.actor.id)
        )
        assert result == "synced"
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await user.execute(query)
    # Replaying the DELETE after inline application is harmless.
    await target.syncer.sync_once("target")
    assert (await target.syncer.status())[0]["last_error"] is None


async def test_real_openfga_invalid_token_recovers_at_latest_position(
    sync_target: SyncTarget, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = sync_target
    await target.syncer.sync_once("target")
    before = await target.snapshot()
    with pytest.raises(ContinuationTokenInvalid):
        await target.store.read_changes("malformed-token")
    async with metadata.transaction(target.db):
        await target.db.execute(
            "UPDATE sync_state SET continuation_token = 'malformed-token' "
            "WHERE consumer = 'pg:target'"
        )

    async def reconcile(connection: str) -> None:
        async with target.syncer._locks(connection):
            assert await target.snapshot() == before

    callback = AsyncMock(side_effect=reconcile)
    monkeypatch.setattr(target.syncer, "_full_reconcile", callback)
    await target.syncer.sync_once("target")
    callback.assert_awaited_once_with("target")
    state = (await target.syncer.status())[0]
    assert state["last_error"] is None
    assert state["continuation_token"] not in {None, "malformed-token"}
    assert not (await target.store.read_changes(state["continuation_token"])).changes
    assert await target.snapshot() == before


async def test_replay_from_beginning_after_grants_revokes_and_group_delete(
    sync_target: SyncTarget,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    unique_name: Callable[[str], str],
) -> None:
    target = sync_target
    rules, actor, group, schema = (
        target.rules,
        target.actor,
        target.group,
        target.admin.schema,
    )
    await rules.grant_table_reader(actor, group, "target", schema, "items")
    await target.syncer.sync_once("target")
    assert await rules.revoke_table_reader(actor, group, "target", schema, "items") == "synced"
    await rules.grant_schema_reader(actor, group, "target", schema)
    await target.syncer.sync_once("target")
    assert await rules.revoke_schema_reader(actor, group, "target", schema) == "synced"
    assert await rules.remove_member(actor, group, actor.id) == "synced"
    await rules.add_member(actor, group, actor.id)
    await rules.grant_table_reader(actor, group, "target", schema, "other")

    deleted = unique_name("gone")
    assert await rules.create_group(actor, deleted) == {}
    await rules.add_member(actor, deleted, actor.id)
    await rules.grant_table_reader(actor, deleted, "target", schema, "items")
    await target.syncer.sync_once("target")
    assert await rules.revoke_table_reader(actor, deleted, "target", schema, "items") == "synced"
    assert await rules.delete_group(actor, deleted) == {}
    await target.syncer.sync_once("target")
    before = await target.snapshot()
    async with metadata.transaction(target.db):
        await target.db.execute(
            "UPDATE sync_state SET continuation_token = NULL WHERE consumer = 'pg:target'"
        )
    await target.syncer.sync_once("target")
    assert (await target.syncer.status())[0]["last_error"] is None
    assert await target.snapshot() == before
    assert before.table_select == {(schema, "other", group_role(group))}
    assert before.row_grants == {(group_role(group), schema, "other", "*", "*")}
    assert group_role(deleted) not in before.roles
    async with await connect_as(target.user) as user:
        assert await (
            await user.execute(SQL("SELECT value FROM {}").format(Identifier(schema, "other")))
        ).fetchall() == [(42,)]
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await user.execute(SQL("SELECT value FROM {}").format(Identifier(schema, "items")))


class UnavailableStore:
    def __init__(self, store: PermissionStore) -> None:
        self._store = store

    async def write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
        await self._store.write(writes, deletes)

    async def read(
        self, object: str | None = None, relation: str | None = None, user: str | None = None
    ) -> list[Tuple]:
        return await self._store.read(object, relation, user)

    async def check(self, user: str, relation: str, object: str) -> bool:
        return await self._store.check(user, relation, object)

    async def read_changes(
        self, continuation_token: str | None, page_size: int = 100
    ) -> ChangesPage:
        raise PermissionStoreUnavailable("OpenFGA unavailable")


async def test_unavailable_openfga_records_error_without_touching_pg_or_token(
    sync_target: SyncTarget,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
) -> None:
    target = sync_target
    schema = target.admin.schema
    await target.rules.grant_table_reader(target.actor, target.group, "target", schema, "items")
    await target.syncer.sync_once("target")
    before = await target.snapshot()
    token = (await target.syncer.status())[0]["continuation_token"]

    async def reconcile(connection: str) -> None:
        pytest.fail("unavailable OpenFGA must not initiate reconciliation")

    offline = Syncer(
        target.db,
        UnavailableStore(target.store),
        target.executor,
        target.syncer._locks,
        fga_store_id=target.syncer._store_id,
        poll_interval_s=2,
        full_reconcile=reconcile,
    )
    await offline.sync_once("target")
    state = (await offline.status())[0]
    assert state["continuation_token"] == token
    assert state["fail_count"] == 1
    assert "OpenFGA unavailable" in (state["last_error"] or "")
    assert await target.snapshot() == before
    async with await connect_as(target.user) as user:
        assert await (
            await user.execute(SQL("SELECT value FROM {}").format(Identifier(schema, "items")))
        ).fetchall() == [(42,)]
    async with target.db.execute("SELECT kind, error FROM audit_log WHERE kind = 'sync'") as cursor:
        (row,) = await cursor.fetchall()
    assert row == ("sync", "PermissionStoreUnavailable: OpenFGA unavailable")
