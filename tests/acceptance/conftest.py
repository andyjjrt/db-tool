"""Shared harness for the plan §5 acceptance tests.

``stack`` wires the real pieces the gateway runs in production (RuleService, Syncer,
Reconciler, PgExecutor on the non-superuser ``target_admin``, real OpenFGA) and hands
tests helpers to create users and groups. The oracle is always a real ``u_*`` password
login: tests assert on rows returned or ``permission denied``, never on catalog state.
"""

from __future__ import annotations

import inspect
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import LiteralString

import aiosqlite
import psycopg
import pytest
import pytest_asyncio
from psycopg.sql import SQL, Composed, Identifier, Literal

from db_gateway import metadata
from db_gateway.permissions import scan
from db_gateway.permissions.admin import AdminUser
from db_gateway.permissions.context import ConnectionLocks
from db_gateway.permissions.executor import PgExecutor
from db_gateway.permissions.reconciler import Reconciler
from db_gateway.permissions.rules import RuleService
from db_gateway.permissions.store import (
    ChangesPage,
    PermissionStore,
    PermissionStoreUnavailable,
    Tuple,
)
from db_gateway.permissions.store_openfga import OpenFgaStore
from db_gateway.permissions.syncer import Syncer
from db_gateway.permissions.types import group_role, user_role
from tests.conftest import RoleInfo
from tests.integration.test_target_db import TargetAdmin
from tests.integration.test_target_db import target_admin as target_admin  # noqa: F401

CONNECTION = "target"
INITIAL_ADMIN_KEY = "initial_boss"
ROWS = [(1, "a", "apple pie"), (2, "a", "apple tart"), (3, "b", "apple juice"), (4, "c", "banana")]
ALL_TEAMS = ["a", "a", "b", "c"]

HAS_SCANNER_ARG = "scanner" in inspect.signature(RuleService.__init__).parameters
needs_scanner = pytest.mark.skipif(
    not HAS_SCANNER_ARG, reason="waiting on w5-api: RuleService has no scanner= argument yet"
)


class GatedStore:
    """Delegates to a real store; tests flip it to simulate an OpenFGA outage.

    ``changes_down`` only breaks the change stream (what the Syncer reads);
    ``all_down`` breaks every call (what the admin API sees). ``before_write``
    runs just before a write reaches OpenFGA.
    """

    def __init__(self, store: PermissionStore) -> None:
        self._store = store
        self.changes_down = False
        self.all_down = False
        self.before_write: Callable[[Sequence[Tuple], Sequence[Tuple]], Awaitable[None]] | None = (
            None
        )

    def _check(self) -> None:
        if self.all_down:
            raise PermissionStoreUnavailable("OpenFGA unavailable")

    async def write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
        self._check()
        if self.before_write is not None:
            await self.before_write(writes, deletes)
        await self._store.write(writes, deletes)

    async def read(
        self, object: str | None = None, relation: str | None = None, user: str | None = None
    ) -> list[Tuple]:
        self._check()
        return await self._store.read(object, relation, user)

    async def check(self, user: str, relation: str, object: str) -> bool:
        self._check()
        return await self._store.check(user, relation, object)

    async def read_changes(
        self, continuation_token: str | None, page_size: int = 100
    ) -> ChangesPage:
        self._check()
        if self.changes_down:
            raise PermissionStoreUnavailable("OpenFGA unavailable")
        return await self._store.read_changes(continuation_token, page_size)


class FixedStats:
    async def distinct_count(
        self, connection: str, schema: str, table: str, column: str, limit: int
    ) -> int:
        return 3


class AdminScanner:
    """The scanner RuleService asks about unsafe views, backed by the real catalog scan."""

    def __init__(self, connect: Callable[[str], Awaitable[psycopg.AsyncConnection]]) -> None:
        self._connect = connect

    async def unsafe_views(
        self, connection: str, tables: Sequence[tuple[str, str]]
    ) -> list[scan.UnsafeView]:
        async with await self._connect(connection) as conn:
            return await scan.unsafe_views(conn, tables)


@dataclass(frozen=True, slots=True)
class Person:
    id: int
    login: RoleInfo

    @property
    def admin_user(self) -> AdminUser:
        return AdminUser(self.id, self.login.name)


@dataclass
class Stack:
    db: aiosqlite.Connection
    store: GatedStore
    executor: PgExecutor
    locks: ConnectionLocks
    syncer: Syncer
    reconciler: Reconciler
    rules: RuleService
    admin: TargetAdmin
    actor: AdminUser
    connect: Callable[[str], Awaitable[psycopg.AsyncConnection]]
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]]
    superuser: psycopg.AsyncConnection
    unique_name: Callable[[str], str]
    people: list[Person] = field(default_factory=list)

    @property
    def schema(self) -> str:
        return self.admin.schema

    def rel(self, table: str = "items") -> Identifier:
        return Identifier(self.schema, table)

    async def sync(self) -> None:
        await self.syncer.sync_once(CONNECTION)
        status = (await self.syncer.status())[0]
        assert status["last_error"] is None, status

    async def admin_sql(
        self, statement: LiteralString | SQL | Composed, *params: object
    ) -> list[tuple[object, ...]]:
        async with await self.connect(CONNECTION) as conn:
            cursor = await conn.execute(statement, params or None)
            return await cursor.fetchall() if cursor.description else []

    async def new_user(self, label: str = "user") -> Person:
        user_id = secrets.randbits(48)
        login = RoleInfo(user_role(user_id), f"pw{secrets.token_hex(8)}")
        async with metadata.transaction(self.db):
            await self.db.execute(
                "INSERT INTO users (id, login_key) VALUES (?, ?)", (user_id, f"{label}{user_id}")
            )
        async with await self.connect(CONNECTION) as conn:
            await conn.execute(
                SQL("CREATE ROLE {} LOGIN INHERIT PASSWORD {}").format(
                    Identifier(login.name), Literal(login.password)
                )
            )
            await conn.execute(
                SQL("GRANT gw_managed TO {} WITH INHERIT TRUE").format(Identifier(login.name))
            )
        person = Person(user_id, login)
        self.people.append(person)
        return person

    async def new_group(self, label: str, *members: Person) -> str:
        """Create a group, let the Syncer create its role, then add the members."""
        name = self.unique_name(label)
        await self.rules.create_group(self.actor, name)
        await self.sync()
        for member in members:
            await self.rules.add_member(self.actor, name, member.id)
        await self.sync()
        return name

    async def teams(self, person: Person, table: str = "items") -> list[str]:
        """Teams of the rows ``person`` can read through a real login; may raise."""
        async with await self.connect_as(person.login) as conn:
            cursor = await conn.execute(
                SQL("SELECT team FROM {} ORDER BY id").format(self.rel(table))
            )
            return [row[0] for row in await cursor.fetchall()]

    async def denied(self, person: Person, table: str = "items") -> bool:
        try:
            await self.teams(person, table)
        except psycopg.errors.InsufficientPrivilege:
            return True
        return False

    async def role_exists(self, role: str) -> bool:
        rows = await self.admin_sql("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s", role)
        return bool(rows)

    async def declare(self, table: str = "items") -> None:
        await self.rules.declare_row_policy(self.actor, CONNECTION, self.schema, table, "team")

    async def row_set(self, group: str, value: str, table: str = "items") -> None:
        await self.rules.grant_row_set(
            self.actor, group, CONNECTION, self.schema, table, "team", value
        )


@pytest_asyncio.fixture
async def stack(
    cluster_lock: psycopg.AsyncConnection | None,
    target_admin: TargetAdmin,  # noqa: F811
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    superuser_conn: psycopg.AsyncConnection,
    unique_name: Callable[[str], str],
    fga_store: str,
    openfga_url: str,
) -> AsyncIterator[Stack]:
    async def connect(name: str) -> psycopg.AsyncConnection:
        assert name == CONNECTION
        return await connect_as(target_admin.login)

    db = await metadata.connect(":memory:")
    raw = OpenFgaStore(openfga_url, fga_store)
    store = GatedStore(raw)
    syncer: Syncer | None = None
    try:
        await metadata.migrate(db)
        await raw.ensure_model()
        actor_id = secrets.randbits(48)
        async with metadata.transaction(db):
            await db.execute(
                "INSERT INTO users (id, login_key) VALUES (?, ?)", (actor_id, INITIAL_ADMIN_KEY)
            )
            await db.execute(
                "INSERT INTO connections (name, host, dbname, admin_secret_ref, "
                "default_privilege_owners) VALUES (?, 'h', 'd', 'ref', ?)",
                (CONNECTION, '["' + target_admin.login.name + '"]'),
            )
        async with await connect(CONNECTION) as conn:
            await conn.execute(
                SQL(
                    "CREATE TABLE {} (id integer PRIMARY KEY, team text NOT NULL, body text)"
                ).format(Identifier(target_admin.schema, "items"))
            )
            await conn.execute(
                SQL(
                    "CREATE TABLE {} (id integer PRIMARY KEY, team text NOT NULL, body text)"
                ).format(Identifier(target_admin.schema, "plain"))
            )
            for table in ("items", "plain"):
                for row in ROWS:
                    await conn.execute(
                        SQL("INSERT INTO {} VALUES (%s, %s, %s)").format(
                            Identifier(target_admin.schema, table)
                        ),
                        row,
                    )
        locks = ConnectionLocks()
        executor = PgExecutor(connect)
        reconciler = Reconciler(db, store, executor, connect, locks)
        syncer = Syncer(
            db,
            store,
            executor,
            locks,
            fga_store_id=fga_store,
            poll_interval_s=2,
            full_reconcile=reconciler.reconcile_strict,
        )
        extra = {"scanner": AdminScanner(connect)} if HAS_SCANNER_ARG else {}
        rules = RuleService(
            db,
            store,
            executor,
            FixedStats(),
            initial_admins=frozenset({INITIAL_ADMIN_KEY}),
            inline=syncer,
            locks=locks,
            **extra,  # pyright: ignore[reportArgumentType]
        )
        yield Stack(
            db,
            store,
            executor,
            locks,
            syncer,
            reconciler,
            rules,
            target_admin,
            AdminUser(actor_id, INITIAL_ADMIN_KEY),
            connect,
            connect_as,
            superuser_conn,
            unique_name,
        )
    finally:
        if syncer is not None:
            await syncer.stop()
        await raw.aclose()
        await db.close()


__all__ = ["ALL_TEAMS", "CONNECTION", "ROWS", "Person", "Stack", "group_role", "stack"]
