"""Reconciler against a real target DB through a non-superuser admin account (plan §10)."""

from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import LiteralString

import aiosqlite
import psycopg
import pytest
import pytest_asyncio
from psycopg.sql import SQL, Composable, Identifier, Literal

from db_gateway import metadata
from db_gateway.permissions import ids
from db_gateway.permissions.context import ConnectionLocks
from db_gateway.permissions.executor import PgExecutor
from db_gateway.permissions.mapping import grant_ops, revoke_ops
from db_gateway.permissions.reconciler import Drift, Reconciler, ReconcileReport
from db_gateway.permissions.store import Tuple
from db_gateway.permissions.store_memory import MemoryStore
from db_gateway.permissions.types import (
    CreateGroupRole,
    DeleteRowGrant,
    DropGroupRole,
    EnableRowPolicy,
    GrantMembership,
    MappingContext,
    RevokeTableSelect,
    user_role,
)
from tests.conftest import RoleInfo
from tests.integration.test_target_db import TargetAdmin
from tests.integration.test_target_db import target_admin as target_admin

pytestmark = pytest.mark.integration


@dataclass(slots=True)
class World:
    admin: TargetAdmin
    db: aiosqlite.Connection
    store: MemoryStore
    executor: PgExecutor
    reconciler: Reconciler
    connect: Callable[[str], Awaitable[psycopg.AsyncConnection]]
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]]
    group: str  # SQLite group name
    user_id: int
    user: RoleInfo

    @property
    def role(self) -> str:
        return f"g_{self.group}"

    @property
    def context(self) -> MappingContext:
        return MappingContext(
            connections=("target",),
            default_privilege_owners={"target": (self.admin.login.name,)},
        )

    def table(self, name: str = "items") -> str:
        return ids.db_table("target", self.admin.schema, name)

    @property
    def member(self) -> Tuple:
        return Tuple(ids.user(self.user_id), "member", ids.group(self.group))

    @property
    def declare(self) -> Tuple:
        return Tuple(ids.column("team"), "row_column", self.table())

    @property
    def table_reader(self) -> Tuple:
        return Tuple(ids.group_member(self.group), "reader", self.table())

    def row_reader(self, value: str) -> Tuple:
        set_id = ids.row_set("target", self.admin.schema, "items", "team", value)
        return Tuple(ids.group_member(self.group), "reader", set_id)

    async def converge(self, *tuples: Tuple) -> None:
        """Write tuples and apply their ops, as the Syncer would have."""
        await self.store.write(writes=tuples)
        ops = [t.op for item in tuples for t in grant_ops(item, self.context)]
        await self.executor.apply("target", ops)

    async def admin_sql(
        self, statement: LiteralString, *params: Composable
    ) -> list[tuple[object, ...]]:
        async with await self.connect("target") as conn:
            cursor = await conn.execute(SQL(statement).format(*params))
            rows = await cursor.fetchall() if cursor.description else []
        return rows

    async def user_teams(self) -> list[str]:
        async with await self.connect_as(self.user) as conn:
            cursor = await conn.execute(
                SQL("SELECT team FROM {} ORDER BY team").format(
                    Identifier(self.admin.schema, "items")
                )
            )
            return [row[0] for row in await cursor.fetchall()]

    async def audit_rows(self) -> list[tuple[str, int, dict[str, object]]]:
        async with self.db.execute(
            "SELECT kind, connection_id, detail FROM audit_log ORDER BY id"
        ) as cur:
            return [(k, c, json.loads(d)) for k, c, d in await cur.fetchall()]


async def settled(world: World) -> ReconcileReport:
    report = await world.reconciler.reconcile("target")
    assert report.error is None
    return report


@pytest_asyncio.fixture
async def world(
    cluster_lock: psycopg.AsyncConnection | None,
    target_admin: TargetAdmin,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    unique_name: Callable[[str], str],
) -> AsyncIterator[World]:
    async def connect(name: str) -> psycopg.AsyncConnection:
        if name != "target":
            raise ConnectionError(f"cannot reach {name}")
        return await connect_as(target_admin.login)

    db = await metadata.connect(":memory:")
    try:
        await metadata.migrate(db)
        group = unique_name("grp")
        async with metadata.transaction(db):
            for name in ("target", "broken"):
                await db.execute(
                    "INSERT INTO connections (name, host, dbname, admin_secret_ref, "
                    "default_privilege_owners) VALUES (?, 'h', 'd', 'ref', ?)",
                    (name, json.dumps([target_admin.login.name])),
                )
            await db.execute("INSERT INTO groups (name) VALUES (?)", (group,))
        executor = PgExecutor(connect)
        store = MemoryStore()
        reconciler = Reconciler(db, store, executor, connect, ConnectionLocks())
        await executor.apply("target", [CreateGroupRole(f"g_{group}")])
        user_id = secrets.randbits(48)
        user = RoleInfo(user_role(user_id), "reconciler-test-password")
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
                    SQL("CREATE TABLE {} (team text NOT NULL)").format(
                        Identifier(target_admin.schema, table)
                    )
                )
                await conn.execute(
                    SQL("INSERT INTO {} VALUES ('a'), ('b'), ('c')").format(
                        Identifier(target_admin.schema, table)
                    )
                )
        yield World(
            target_admin, db, store, executor, reconciler, connect, connect_as, group, user_id, user
        )
    finally:
        await db.close()


def kinds(reported: list[Drift]) -> list[str]:
    return sorted(d.kind for d in reported)


async def test_applied_tuples_reconcile_to_nothing(world: World) -> None:
    schema_reader = Tuple(
        ids.group_member(world.group), "reader", ids.db_schema("target", world.admin.schema)
    )
    await world.converge(world.member, schema_reader, world.declare)
    report = await settled(world)
    assert (report.fixes, report.reported, report.skipped, report.failed) == ([], [], [], [])
    assert await world.audit_rows() == []


async def test_row_set_state_reconciles_to_nothing(world: World) -> None:
    other = f"{world.group[:30]}_two"
    async with metadata.transaction(world.db):
        await world.db.execute("INSERT INTO groups (name) VALUES (?)", (other,))
    await world.executor.apply("target", [CreateGroupRole(f"g_{other}")])
    second = Tuple(
        ids.group_member(other),
        "reader",
        ids.row_set("target", world.admin.schema, "items", "team", "c"),
    )
    await world.converge(
        world.declare, world.member, world.row_reader("b"), world.table_reader, second
    )
    report = await settled(world)
    assert (report.fixes, report.reported) == ([], [])


async def test_manual_grant_is_removed_and_audited(world: World) -> None:
    await world.converge(world.member, world.table_reader)
    await world.admin_sql(
        "GRANT SELECT ON TABLE {} TO {}",
        Identifier(world.admin.schema, "other"),
        Identifier(world.role),
    )
    report = await settled(world)
    assert report.fixes == [RevokeTableSelect(world.admin.schema, "other", world.role)]
    assert report.reported == []
    rows = await world.admin_sql(
        "SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
        "ON n.oid = c.relnamespace, LATERAL aclexplode(c.relacl) a "
        "WHERE n.nspname = {} AND c.relname = 'other' AND a.grantee = {}::regrole",
        Literal(world.admin.schema),
        Literal(world.role),
    )
    assert rows == []
    audit = await world.audit_rows()
    assert len(audit) == 1
    kind, connection_id, detail = audit[0]
    assert (kind, connection_id) == ("sync", 1)
    assert detail["fixes"] == [
        {
            "op": "RevokeTableSelect",
            "schema": world.admin.schema,
            "table": "other",
            "role": world.role,
        }
    ]
    assert (await settled(world)).fixes == []
    assert len(await world.audit_rows()) == 1


async def test_dry_run_reports_the_fix_without_changing_pg(world: World) -> None:
    await world.converge(world.member, world.table_reader)
    await world.admin_sql(
        "GRANT SELECT ON TABLE {} TO {}",
        Identifier(world.admin.schema, "other"),
        Identifier(world.role),
    )
    dry = await world.reconciler.reconcile("target", dry_run=True)
    assert dry.fixes == [RevokeTableSelect(world.admin.schema, "other", world.role)]
    assert await world.audit_rows() == []
    again = await world.reconciler.reconcile("target", dry_run=True)
    assert again.fixes == dry.fixes
    real = await settled(world)
    assert real.fixes == dry.fixes


async def test_disabled_rls_is_restored_and_user_is_filtered_again(world: World) -> None:
    await world.converge(world.declare, world.member, world.row_reader("b"))
    assert await world.user_teams() == ["b"]
    await world.admin_sql(
        "ALTER TABLE {} DISABLE ROW LEVEL SECURITY", Identifier(world.admin.schema, "items")
    )
    assert await world.user_teams() == ["a", "b", "c"]
    report = await settled(world)
    assert report.fixes == [EnableRowPolicy(world.admin.schema, "items", "team")]
    assert await world.user_teams() == ["b"]
    assert (await settled(world)).fixes == []


@pytest.mark.parametrize("damage", ["drop_read", "drop_passthrough", "replace_read", "revoke"])
async def test_damaged_policy_state_is_repaired(world: World, damage: str) -> None:
    await world.converge(world.declare, world.member, world.row_reader("b"))
    items = Identifier(world.admin.schema, "items")
    statements: dict[str, tuple[LiteralString, tuple[Composable, ...]]] = {
        "drop_read": ("DROP POLICY gw_read ON {}", (items,)),
        "drop_passthrough": ("DROP POLICY gw_passthrough ON {}", (items,)),
        "replace_read": ("ALTER POLICY gw_read ON {} USING (true)", (items,)),
        "revoke": ("REVOKE SELECT ON TABLE {} FROM gw_managed", (items,)),
    }
    statement, params = statements[damage]
    await world.admin_sql(statement, *params)
    report = await settled(world)
    assert report.fixes == [EnableRowPolicy(world.admin.schema, "items", "team")]
    assert await world.user_teams() == ["b"]
    assert (await settled(world)).fixes == []


async def test_permissive_policy_damage_is_repaired(world: World) -> None:
    await world.converge(world.declare, world.member, world.row_reader("b"))
    schema = Literal(world.admin.schema)
    items = Identifier(world.admin.schema, "items")
    for policy, expression in (
        (
            "gw_read",
            SQL(
                "(SELECT gateway_acl.allow_all({s}, 'items')) OR team = ANY "
                "((SELECT gateway_acl.allowed_values({s}, 'items'))::text[]) OR true"
            ).format(s=schema),
        ),
        (
            "gw_passthrough",
            SQL("NOT (SELECT gateway_acl.is_managed() UNION SELECT false ORDER BY 1 LIMIT 1)"),
        ),
    ):
        assert await world.user_teams() == ["b"]
        await world.admin_sql(
            "ALTER POLICY {} ON {} USING ({})", Identifier(policy), items, expression
        )
        assert await world.user_teams() == ["a", "b", "c"]
        report = await settled(world)
        assert report.fixes == [EnableRowPolicy(world.admin.schema, "items", "team")], policy
        assert await world.user_teams() == ["b"]
        assert (await settled(world)).fixes == []


async def test_policy_with_shadowing_operator_is_repaired(world: World) -> None:
    """A public.= operator on a varchar column must not deparse like the built-in one."""
    items = Identifier(world.admin.schema, "items")
    await world.admin_sql("ALTER TABLE {} ALTER COLUMN team TYPE varchar", items)
    await world.converge(world.declare, world.member, world.row_reader("b"))
    assert await world.user_teams() == ["b"]
    assert (await settled(world)).fixes == []
    func = Identifier("public", f"gw_test_eq_{secrets.token_hex(4)}")
    try:
        await world.admin_sql(
            "CREATE FUNCTION {} (varchar, text) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
            func,
        )
        await world.admin_sql(
            "CREATE OPERATOR public.= (LEFTARG = varchar, RIGHTARG = text, FUNCTION = {})", func
        )
        await world.admin_sql(
            "ALTER POLICY gw_read ON {} USING ((SELECT gateway_acl.allow_all({}, 'items')) "
            "OR team OPERATOR(public.=) ANY "
            "((SELECT gateway_acl.allowed_values({}, 'items'))::text[]))",
            items,
            Literal(world.admin.schema),
            Literal(world.admin.schema),
        )
        assert await world.user_teams() == ["a", "b", "c"]
        report = await settled(world)
        assert report.fixes == [EnableRowPolicy(world.admin.schema, "items", "team")]
        assert await world.user_teams() == ["b"]
        assert (await settled(world)).fixes == []
    finally:
        await world.admin_sql("DROP OPERATOR IF EXISTS public.= (varchar, text)")
        await world.admin_sql("DROP FUNCTION IF EXISTS {} (varchar, text)", func)


async def test_extra_permissive_policy_on_declared_table_is_reported(world: World) -> None:
    await world.converge(world.declare, world.member, world.row_reader("b"))
    items = Identifier(world.admin.schema, "items")
    await world.admin_sql("CREATE POLICY open_all ON {} FOR SELECT USING (true)", items)
    assert await world.user_teams() == ["a", "b", "c"]
    report = await settled(world)
    assert report.fixes == []
    assert [d.kind for d in report.reported] == ["extra_policy"]


@pytest.mark.parametrize("other", ["team ", "team\t"])
async def test_policy_on_lookalike_column_is_repaired(world: World, other: str) -> None:
    """Whitespace inside a quoted identifier is data: "team " is not "team"."""
    await world.converge(world.declare, world.member, world.row_reader("b"))
    items = Identifier(world.admin.schema, "items")
    await world.admin_sql(
        "ALTER TABLE {} ADD COLUMN {} text NOT NULL DEFAULT 'b'", items, Identifier(other)
    )
    await world.executor.apply("target", [EnableRowPolicy(world.admin.schema, "items", other)])
    assert await world.user_teams() == ["a", "b", "c"]
    report = await settled(world)
    assert report.fixes == [EnableRowPolicy(world.admin.schema, "items", "team")]
    assert await world.user_teams() == ["b"]
    assert (await settled(world)).fixes == []


@pytest.mark.parametrize("role", ["user", "gw_managed"])
async def test_unexpected_row_grant_of_any_role_is_deleted(world: World, role: str) -> None:
    await world.converge(world.declare, world.member, world.row_reader("b"))
    schema = world.admin.schema
    name = world.user.name if role == "user" else "gw_managed"
    await world.admin_sql(
        "INSERT INTO gateway_acl.row_grants VALUES ({}, {}, 'items', 'team', '*')",
        Literal(name),
        Literal(schema),
    )
    assert await world.user_teams() == ["a", "b", "c"]
    report = await settled(world)
    assert report.fixes == [DeleteRowGrant(name, schema, "items", "*")]
    assert await world.user_teams() == ["b"]
    assert (await settled(world)).fixes == []


async def test_non_inheriting_membership_is_restored(world: World) -> None:
    await world.converge(world.member, world.table_reader)

    async def can_read() -> bool:
        async with await world.connect_as(world.user) as conn:
            try:
                await conn.execute(
                    SQL("SELECT 1 FROM {}").format(Identifier(world.admin.schema, "items"))
                )
            except psycopg.errors.InsufficientPrivilege:
                return False
            return True

    assert await can_read()
    await world.admin_sql(
        "GRANT {} TO {} WITH INHERIT FALSE, SET FALSE",
        Identifier(world.role),
        Identifier(world.user.name),
    )
    assert not await can_read()
    report = await settled(world)
    assert report.fixes == [GrantMembership(world.role, world.user.name)]
    assert await can_read()
    assert (await settled(world)).fixes == []


async def test_foreign_grantor_membership_is_reported_and_not_revoked(
    world: World, superuser_conn: psycopg.AsyncConnection
) -> None:
    await superuser_conn.execute(
        SQL("GRANT {} TO {}").format(Identifier(world.role), Identifier(world.user.name))
    )
    dry = await world.reconciler.reconcile("target", dry_run=True)
    assert dry.fixes == []
    assert "membership_grantor" in kinds(dry.reported)
    real = await settled(world)
    assert real.fixes == [] and real.failed == []
    assert "membership_grantor" in kinds(real.reported)


async def test_missing_group_role_is_recreated(world: World) -> None:
    await world.converge(world.member, world.table_reader)
    revokes = [t.op for t in revoke_ops(world.table_reader, world.context)]
    await world.executor.apply("target", [*revokes, DropGroupRole(world.role)])
    report = await settled(world)
    assert report.fixes[0] == CreateGroupRole(world.role)
    assert GrantMembership(world.role, world.user.name) in report.fixes
    assert (await settled(world)).fixes == []


async def test_orphan_row_grant_is_deleted(world: World) -> None:
    schema = world.admin.schema
    await world.admin_sql(
        "INSERT INTO gateway_acl.row_grants VALUES ('g_nobody', {}, 'items', 'team', 'z')",
        Literal(schema),
    )
    report = await settled(world)
    assert report.fixes == [DeleteRowGrant("g_nobody", schema, "items", "z")]
    assert await world.admin_sql("SELECT 1 FROM gateway_acl.row_grants") == []


async def test_policies_on_an_undeclared_table_are_only_reported(world: World) -> None:
    schema = world.admin.schema
    await world.executor.apply("target", [EnableRowPolicy(schema, "other", "team")])
    report = await settled(world)
    assert report.fixes == []
    assert kinds(report.reported) == ["undeclared_policy"]
    rows = await world.admin_sql(
        "SELECT polname FROM pg_catalog.pg_policy WHERE polrelid = {}::regclass ORDER BY 1",
        Literal(f'"{schema}"."other"'),
    )
    assert rows == [("gw_passthrough",), ("gw_read",)]
    assert await world.audit_rows() == []


async def test_grantor_drift_and_missing_managed_usage_are_only_reported(
    world: World, superuser_conn: psycopg.AsyncConnection
) -> None:
    await world.converge(world.table_reader)
    await superuser_conn.execute(
        SQL("GRANT {} TO {}").format(Identifier(world.role), Identifier(world.user.name))
    )
    await world.admin_sql(
        "REVOKE USAGE ON SCHEMA {} FROM gw_managed", Identifier(world.admin.schema)
    )
    await world.store.write(writes=[world.member])
    report = await settled(world)
    assert report.fixes == []
    assert kinds(report.reported) == ["managed_usage_missing", "membership_grantor"]


async def test_reconcile_all_survives_a_failing_connection(world: World) -> None:
    await world.converge(world.member, world.table_reader)
    await world.admin_sql(
        "GRANT SELECT ON TABLE {} TO {}",
        Identifier(world.admin.schema, "other"),
        Identifier(world.role),
    )
    reports = await world.reconciler.reconcile_all()
    assert set(reports) == {"target", "broken"}
    assert reports["broken"].error is not None and "cannot reach" in reports["broken"].error
    assert reports["target"].fixes == [RevokeTableSelect(world.admin.schema, "other", world.role)]
