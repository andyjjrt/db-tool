"""Exercise executor changes and catalog snapshots through a real target admin."""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Literal as LiteralType

import psycopg
import pytest
import pytest_asyncio
from psycopg.sql import SQL, Identifier, Literal

from db_gateway.permissions import actual, ids
from db_gateway.permissions.executor import ApplyError, PgExecutor, TransientApplyError
from db_gateway.permissions.executor_protocol import Executor
from db_gateway.permissions.mapping import grant_ops, revoke_ops
from db_gateway.permissions.store import Tuple
from db_gateway.permissions.types import (
    CreateGroupRole,
    DeleteRowGrant,
    DisableRowPolicy,
    DropGroupRole,
    EnableRowPolicy,
    GrantAllTablesSelect,
    GrantDefaultSelect,
    GrantMembership,
    GrantSchemaUsage,
    GrantTableSelect,
    MappingContext,
    PgOp,
    RevokeMembership,
    RevokeTableSelect,
    UpsertRowGrant,
    user_role,
)
from tests.conftest import PG_USER, RoleInfo
from tests.integration.test_target_db import TargetAdmin
from tests.integration.test_target_db import target_admin as target_admin

pytestmark = pytest.mark.integration


@dataclass(frozen=True, slots=True)
class ApplyTarget:
    admin: TargetAdmin
    executor: PgExecutor
    connect: Callable[[str], Awaitable[psycopg.AsyncConnection]]
    group: str
    user_id: int
    user: RoleInfo

    @property
    def context(self) -> MappingContext:
        return MappingContext(
            connections=("target",),
            default_privilege_owners={"target": (self.admin.login.name,)},
        )

    def rule(self, kind: str, *, group: str | None = None, value: str = "b") -> Tuple:
        group_name = (group or self.group).removeprefix("g_")
        if kind == "membership":
            return Tuple(ids.user(self.user_id), "member", ids.group(group_name))
        objects = {
            "schema": ids.db_schema("target", self.admin.schema),
            "table": ids.db_table("target", self.admin.schema, "items"),
            "row_set": ids.row_set("target", self.admin.schema, "items", "team", value),
        }
        return Tuple(ids.group_member(group_name), "reader", objects[kind])

    async def snapshot(self) -> actual.ActualState:
        async with await self.connect("target") as conn:
            return await actual.read_actual(
                conn,
                schemas=(self.admin.schema,),
                default_privilege_owners=(self.admin.login.name,),
            )


@pytest_asyncio.fixture
async def apply_target(
    cluster_lock: psycopg.AsyncConnection | None,
    target_admin: TargetAdmin,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    unique_name: Callable[[str], str],
) -> ApplyTarget:
    async def connect(name: str) -> psycopg.AsyncConnection:
        assert name == "target"
        return await connect_as(target_admin.login)

    executor = PgExecutor(connect)
    protocol: Executor = executor
    group = unique_name("g")
    await protocol.apply("target", [CreateGroupRole(group)])
    user_id = secrets.randbits(48)
    user = RoleInfo(user_role(user_id), "apply-test-password")
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
    return ApplyTarget(target_admin, executor, connect, group, user_id, user)


async def _catalog_snapshot(
    conn: psycopg.AsyncConnection, schema: str
) -> tuple[list[tuple[object, ...]], ...]:
    """Compare catalog contents, normalizing NULL ACL to PostgreSQL's default ACL.

    GRANT followed by REVOKE can materialize an owner's implicit relacl without
    changing privileges. Policies omit their allocation OIDs for the same reason.
    """
    queries = (
        SQL(
            "SELECT c.relname, a.grantor, a.grantee, a.privilege_type, a.is_grantable "
            "FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))) a "
            "WHERE n.nspname = {} AND c.relkind IN ('r', 'p') ORDER BY 1, 2, 3, 4"
        ).format(Literal(schema)),
        SQL(
            "SELECT defaclrole, defaclnamespace, defaclobjtype, defaclacl::text "
            "FROM pg_catalog.pg_default_acl ORDER BY 1, 2, 3"
        ),
        SQL(
            "SELECT roleid, member, grantor, admin_option, inherit_option, set_option "
            "FROM pg_catalog.pg_auth_members ORDER BY 1, 2, 3"
        ),
        SQL(
            "SELECT polrelid, polname, polcmd, polpermissive, polroles::text, "
            "pg_catalog.pg_get_expr(polqual, polrelid), "
            "pg_catalog.pg_get_expr(polwithcheck, polrelid) "
            "FROM pg_catalog.pg_policy ORDER BY 1, 2"
        ),
        SQL(
            "SELECT group_role, schema_name, table_name, column_name, value "
            "FROM gateway_acl.row_grants ORDER BY 1, 2, 3, 4, 5"
        ),
    )
    rows: list[list[tuple[object, ...]]] = []
    for query in queries:
        cursor = await conn.execute(query)
        rows.append(await cursor.fetchall())
    return tuple(rows)


@pytest.mark.parametrize("kind", ["membership", "schema", "table", "row_set"])
async def test_mapping_converges_after_double_grant_and_revoke(
    apply_target: ApplyTarget, kind: str
) -> None:
    target = apply_target
    schema = target.admin.schema
    before = await target.snapshot()
    async with await target.connect("target") as conn:
        before_catalog = await _catalog_snapshot(conn, schema)
    rule = target.rule(kind)
    grants = [item.op for item in grant_ops(rule, target.context)]
    revokes = [item.op for item in revoke_ops(rule, target.context)]
    if kind == "row_set":
        grants.insert(0, EnableRowPolicy(schema, "items", "team"))
        revokes.append(DisableRowPolicy(schema, "items"))

    await target.executor.apply("target", grants)
    after = await target.snapshot()
    assert after.schema_usage == before.schema_usage == frozenset({(schema, "gw_managed")})
    assert after.roles == before.roles
    expected_tables: set[actual.TableSelect] = set()
    expected_defaults: set[actual.DefaultSelect] = set()
    expected_rows: set[actual.RowGrant] = set()
    if kind == "membership":
        assert after.memberships - before.memberships == {
            (target.group, target.user.name, target.admin.login.name, False, True, True)
        }
    else:
        assert after.memberships == before.memberships
    if kind == "schema":
        expected_tables = {(schema, table, target.group) for table in ("items", "other")}
        expected_defaults = {(target.admin.login.name, schema, target.group)}
        expected_rows = {(target.group, schema, "*", "*", "*")}
    elif kind == "table":
        expected_tables = {(schema, "items", target.group)}
        expected_rows = {(target.group, schema, "items", "*", "*")}
    elif kind == "row_set":
        expected_tables = {(schema, "items", "gw_managed")}
        expected_rows = {(target.group, schema, "items", "team", "b")}
    assert after.table_select == expected_tables
    assert after.default_select == expected_defaults
    assert after.row_grants == expected_rows
    if kind == "row_set":
        assert after.row_security == {
            (schema, "items", True, True),
            (schema, "other", False, False),
        }
        assert {p.name for p in after.policies} == {"gw_passthrough", "gw_read"}
        assert {p.roles for p in after.policies} == {("PUBLIC",)}
        assert all(p.permissive and p.using and p.with_check is None for p in after.policies)
    else:
        assert after.row_security == before.row_security
        assert after.policies == before.policies
    await target.executor.apply("target", grants)
    assert await target.snapshot() == after

    await target.executor.apply("target", revokes)
    await target.executor.apply("target", revokes)
    assert await target.snapshot() == before
    async with await target.connect("target") as conn:
        assert await _catalog_snapshot(conn, schema) == before_catalog


async def test_replay_after_group_drop_logs_skips_and_deletes_orphans(
    apply_target: ApplyTarget,
    superuser_conn: psycopg.AsyncConnection,
    caplog: pytest.LogCaptureFixture,
) -> None:
    target = apply_target
    rules = [target.rule("schema"), target.rule("row_set")]
    grants = [item.op for rule in rules for item in grant_ops(rule, target.context)]
    revokes = [item.op for rule in rules for item in revoke_ops(rule, target.context)]
    batches = [grants, revokes, [DropGroupRole(target.group)]]
    for ops in batches:
        await target.executor.apply("target", ops)
    assert target.group not in (await target.snapshot()).roles
    await superuser_conn.execute(
        SQL("INSERT INTO gateway_acl.row_grants VALUES ({}, {}, '*', '*', '*')").format(
            Literal(target.group), Literal(target.admin.schema)
        )
    )
    with caplog.at_level(logging.INFO, logger="db_gateway.permissions.executor"):
        await target.executor.apply("target", grants)
        skipped = target.executor.last_skipped["target"]
        assert [item.op for item in skipped] == grants
        assert all("role" in item.reason for item in skipped)
        await target.executor.apply("target", revokes)
        # DeleteRowGrant runs even though its group no longer exists.
        assert not (await target.snapshot()).row_grants
        await superuser_conn.execute(
            SQL("INSERT INTO gateway_acl.row_grants VALUES ({}, {}, 'orphan', 'team', 'z')").format(
                Literal(target.group), Literal(target.admin.schema)
            )
        )
        await target.executor.apply("target", [DropGroupRole(target.group)])
        assert not target.executor.last_skipped["target"]
    state = await target.snapshot()
    assert not state.row_grants
    assert target.group not in state.roles
    assert len(caplog.records) == len(grants) + 2
    assert all(
        "Skipping op" in record.message and target.group in record.message
        for record in caplog.records
    )


async def test_replay_checks_every_required_object_before_running(
    apply_target: ApplyTarget,
    unique_name: Callable[[str], str],
) -> None:
    target = apply_target
    missing_role = unique_name("g")
    missing_schema = unique_name("gone")
    schema = target.admin.schema
    ops: list[PgOp] = [
        GrantMembership(missing_role, target.user.name),
        GrantMembership(target.group, missing_role),
        RevokeMembership(missing_role, target.user.name),
        RevokeMembership(target.group, missing_role),
        RevokeMembership(target.group, target.user.name),  # both roles exist, no grant
        GrantSchemaUsage(schema, missing_role),
        GrantSchemaUsage(missing_schema, target.group),
        GrantTableSelect(schema, "gone", target.group),
        RevokeTableSelect(schema, "gone", target.group),
        GrantAllTablesSelect(missing_schema, target.group),
        GrantDefaultSelect(missing_role, schema, target.group),
        UpsertRowGrant(missing_role, schema, "items", "team", "b"),
        EnableRowPolicy(schema, "gone", "team"),
        DisableRowPolicy(schema, "gone"),
    ]
    before = await target.snapshot()
    await target.executor.apply("target", ops)
    assert [item.op for item in target.executor.last_skipped["target"]] == ops
    assert await target.snapshot() == before
    # Row-grant replay only requires the group, not its possibly deleted objects.
    await target.executor.apply(
        "target",
        [
            UpsertRowGrant(target.group, missing_schema, "gone", "team", "b"),
            DeleteRowGrant(target.group, missing_schema, "gone", "b"),
        ],
    )
    assert not target.executor.last_skipped["target"]
    assert await target.snapshot() == before


@pytest_asyncio.fixture
async def foreign_database_grant(
    cluster_lock: psycopg.AsyncConnection,
    apply_target: ApplyTarget,
    unique_name: Callable[[str], str],
) -> AsyncIterator[tuple[psycopg.AsyncConnection, str]]:
    """Put a dependency in the lock fixture's separate postgres database."""
    schema = unique_name("remote")
    await cluster_lock.execute(SQL("CREATE SCHEMA {}").format(Identifier(schema)))
    try:
        await cluster_lock.execute(
            SQL("CREATE TABLE {} (id int)").format(Identifier(schema, "dependency"))
        )
        await cluster_lock.execute(
            SQL("GRANT SELECT ON {} TO {}").format(
                Identifier(schema, "dependency"), Identifier(apply_target.group)
            )
        )
        yield cluster_lock, schema
    finally:
        await cluster_lock.execute(SQL("DROP SCHEMA {} CASCADE").format(Identifier(schema)))


async def test_cross_database_role_dependency_is_transient_and_atomic(
    apply_target: ApplyTarget,
    foreign_database_grant: tuple[psycopg.AsyncConnection, str],
) -> None:
    target = apply_target
    await target.executor.apply(
        "target", [UpsertRowGrant(target.group, target.admin.schema, "items", "team", "b")]
    )
    before = await target.snapshot()
    op = DropGroupRole(target.group)
    with pytest.raises(TransientApplyError) as failure:
        await target.executor.apply("target", [op])
    assert failure.value.op == op
    assert isinstance(failure.value.original, psycopg.Error)
    assert failure.value.original.sqlstate == "2BP01"
    assert await target.snapshot() == before
    conn, schema = foreign_database_grant
    await conn.execute(
        SQL("REVOKE SELECT ON {} FROM {}").format(
            Identifier(schema, "dependency"), Identifier(target.group)
        )
    )
    await target.executor.apply("target", [op])
    after = await target.snapshot()
    assert target.group not in after.roles
    assert not after.row_grants


@pytest.mark.parametrize("foreign_grantor", [False, True])
async def test_membership_revoke_uses_the_catalog_grantor(
    apply_target: ApplyTarget,
    superuser_conn: psycopg.AsyncConnection,
    unique_name: Callable[[str], str],
    foreign_grantor: bool,
) -> None:
    target = apply_target
    grantor = unique_name("grantor") if foreign_grantor else target.admin.login.name
    if foreign_grantor:
        await superuser_conn.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(grantor)))
        await superuser_conn.execute(
            SQL("GRANT {} TO {} WITH ADMIN OPTION, INHERIT FALSE, SET FALSE").format(
                Identifier(target.group), Identifier(grantor)
            )
        )
        # PostgreSQL requires the admin to be authorized to act as this grantor.
        await superuser_conn.execute(
            SQL("GRANT {} TO {} WITH INHERIT TRUE, SET TRUE").format(
                Identifier(grantor), Identifier(target.admin.login.name)
            )
        )
        await superuser_conn.execute(
            SQL("GRANT {} TO {} GRANTED BY {}").format(
                Identifier(target.group), Identifier(target.user.name), Identifier(grantor)
            )
        )
    else:
        await target.executor.apply("target", [GrantMembership(target.group, target.user.name)])
    state = await target.snapshot()
    assert (target.group, target.user.name, grantor, False, True, True) in state.memberships
    await target.executor.apply("target", [RevokeMembership(target.group, target.user.name)])
    assert not {
        row
        for row in (await target.snapshot()).memberships
        if row[:2] == (target.group, target.user.name)
    }
    await target.executor.apply("target", [RevokeMembership(target.group, target.user.name)])
    assert len(target.executor.last_skipped["target"]) == 1


async def test_unauthorized_foreign_grantor_revoke_fails_and_rolls_back(
    apply_target: ApplyTarget,
    superuser_conn: psycopg.AsyncConnection,
) -> None:
    target = apply_target
    await superuser_conn.execute(
        SQL("GRANT {} TO {}").format(Identifier(target.group), Identifier(target.user.name))
    )
    before = await target.snapshot()
    assert (target.group, target.user.name, PG_USER, False, True, True) in before.memberships
    op = RevokeMembership(target.group, target.user.name)
    with pytest.raises(ApplyError) as failure:
        await target.executor.apply(
            "target",
            [UpsertRowGrant(target.group, target.admin.schema, "items", "team", "b"), op],
        )
    assert failure.value.op == op
    assert isinstance(failure.value.original, psycopg.errors.InsufficientPrivilege)
    assert await target.snapshot() == before


async def test_group_creation_disables_inheriting_admin_self_grants(
    apply_target: ApplyTarget,
    unique_name: Callable[[str], str],
) -> None:
    target = apply_target
    group = unique_name("g")

    async def connect(name: str) -> psycopg.AsyncConnection:
        conn = await target.connect(name)
        await conn.execute(SQL("SET createrole_self_grant = 'set, inherit'"))
        return conn

    executor = PgExecutor(connect)
    await executor.apply("target", [CreateGroupRole(group), GrantMembership("gw_managed", group)])
    async with await target.connect("target") as conn:
        cursor = await conn.execute(
            SQL(
                "SELECT m.inherit_option, m.set_option FROM pg_catalog.pg_auth_members m "
                "JOIN pg_catalog.pg_roles g ON g.oid = m.roleid "
                "JOIN pg_catalog.pg_roles u ON u.oid = m.member "
                "WHERE g.rolname = {} AND u.rolname = CURRENT_USER"
            ).format(Literal(group))
        )
        assert all(row == (False, False) for row in await cursor.fetchall())
        cursor = await conn.execute(
            SQL("SELECT CURRENT_USER, session_user, gateway_acl.is_managed()")
        )
        assert await cursor.fetchone() == (target.admin.login.name, target.admin.login.name, False)
        cursor = await conn.execute(
            SQL("SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname = {}").format(
                Literal(group)
            )
        )
        assert await cursor.fetchone() == (False,)


async def test_same_connection_applies_hold_the_lock_until_close(
    apply_target: ApplyTarget,
) -> None:
    target = apply_target
    entered = asyncio.Event()
    release = asyncio.Event()
    queued = asyncio.Event()
    opened: list[psycopg.AsyncConnection] = []

    class ObservedLock(asyncio.Lock):
        async def acquire(self) -> LiteralType[True]:
            if self.locked():
                queued.set()
            return await super().acquire()

    async def connect(name: str) -> psycopg.AsyncConnection:
        if opened:
            assert opened[0].closed  # The preceding transaction has committed and closed.
        conn = await target.connect(name)
        opened.append(conn)
        if len(opened) == 1:
            entered.set()
            await release.wait()
        else:
            assert (target.group, target.admin.schema, "items", "team", "a") in (
                await actual.read_row_grants(conn)
            )
        return conn

    executor = PgExecutor(connect)
    lock = ObservedLock()
    executor._locks["target"] = lock
    async with asyncio.timeout(5), asyncio.TaskGroup() as tasks:
        tasks.create_task(
            executor.apply(
                "target",
                [
                    UpsertRowGrant(target.group, target.admin.schema, "items", "team", "a"),
                    UpsertRowGrant(target.group, target.admin.schema, "items", "team", "b"),
                ],
            )
        )
        await entered.wait()
        tasks.create_task(
            executor.apply(
                "target",
                [
                    DeleteRowGrant(target.group, target.admin.schema, "items", "a"),
                    UpsertRowGrant(target.group, target.admin.schema, "items", "team", "c"),
                ],
            )
        )
        await queued.wait()
        assert lock.locked()
        assert len(opened) == 1
        release.set()
    assert not lock.locked()
    assert len(opened) == 2
    assert all(conn.closed for conn in opened)
    assert (await target.snapshot()).row_grants == {
        (target.group, target.admin.schema, "items", "team", value) for value in ("b", "c")
    }


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("table", ["a", "b", "c"]),
        ("schema", ["a", "b", "c"]),
        ("row_set", ["b"]),
        ("union", ["a", "b"]),
        ("none", []),
    ],
)
async def test_real_managed_logins_read_only_their_granted_rows(
    apply_target: ApplyTarget,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    unique_name: Callable[[str], str],
    kind: str,
    expected: list[str],
) -> None:
    target = apply_target
    schema = target.admin.schema
    grants: list[PgOp] = [GrantMembership(target.group, target.user.name)]
    revokes: list[PgOp] = []
    rules: list[Tuple] = []
    if kind == "union":
        other_group = unique_name("g")
        grants.extend(
            [CreateGroupRole(other_group), GrantMembership(other_group, target.user.name)]
        )
        rules = [
            target.rule("row_set", value="a"),
            target.rule("row_set", group=other_group, value="b"),
        ]
    elif kind != "none":
        rules = [target.rule(kind)]
    for rule in rules:
        grants.extend(item.op for item in grant_ops(rule, target.context))
        revokes.extend(item.op for item in revoke_ops(rule, target.context))
    # Existing table/schema readers must retain access when RLS is enabled later.
    grants.append(EnableRowPolicy(schema, "items", "team"))
    await target.executor.apply("target", grants)
    async with await connect_as(target.user) as conn:
        cursor = await conn.execute(
            SQL("SELECT team FROM {} ORDER BY team").format(Identifier(schema, "items"))
        )
        assert [row[0] for row in await cursor.fetchall()] == expected
        query = SQL("SELECT team FROM {} ORDER BY team").format(Identifier(schema, "other"))
        if kind == "schema":
            cursor = await conn.execute(query)
            assert [row[0] for row in await cursor.fetchall()] == ["a", "b", "c"]
        else:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                await conn.execute(query)

        await target.executor.apply("target", revokes)
        cursor = await conn.execute(
            SQL("SELECT team FROM {} ORDER BY team").format(Identifier(schema, "items"))
        )
        assert await cursor.fetchall() == []
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await conn.execute(query)


@pytest.mark.parametrize("revoke", [False, True])
async def test_privilege_warning_rolls_back_the_whole_change(
    apply_target: ApplyTarget,
    superuser_conn: psycopg.AsyncConnection,
    unique_name: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
    revoke: bool,
) -> None:
    target = apply_target
    foreign_schema = unique_name("foreign")
    await superuser_conn.execute(SQL("CREATE SCHEMA {}").format(Identifier(foreign_schema)))
    await superuser_conn.execute(
        SQL("CREATE TABLE {} (team text)").format(Identifier(foreign_schema, "foreign_table"))
    )
    await superuser_conn.execute(
        SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
            Identifier(foreign_schema), Identifier(target.admin.login.name)
        )
    )
    # SELECT without GRANT OPTION produces 01007/01006 rather than a hard
    # permission-denied error. Neither warning may be mistaken for success.
    await superuser_conn.execute(
        SQL("GRANT SELECT ON {} TO {}").format(
            Identifier(foreign_schema, "foreign_table"), Identifier(target.admin.login.name)
        )
    )
    if revoke:
        await superuser_conn.execute(
            SQL("GRANT SELECT ON {} TO {}").format(
                Identifier(foreign_schema, "foreign_table"), Identifier(target.group)
            )
        )
    removed: list[psycopg.AsyncConnection] = []
    opened: list[psycopg.AsyncConnection] = []

    async def connect(name: str) -> psycopg.AsyncConnection:
        conn = await target.connect(name)
        await conn.execute(SQL("SET client_min_messages = 'error'"))
        opened.append(conn)
        remove = conn.remove_notice_handler

        def remove_notice(handler: Callable[[psycopg.errors.Diagnostic], None]) -> None:
            remove(handler)
            removed.append(conn)

        monkeypatch.setattr(conn, "remove_notice_handler", remove_notice)
        return conn

    executor = PgExecutor(connect)
    before = await target.snapshot()
    new_group = unique_name("g")
    op = (
        RevokeTableSelect(foreign_schema, "foreign_table", target.group)
        if revoke
        else GrantTableSelect(foreign_schema, "foreign_table", target.group)
    )
    with pytest.raises(ApplyError) as failure:
        await executor.apply(
            "target",
            [
                CreateGroupRole(new_group),
                GrantTableSelect(target.admin.schema, "items", target.group),
                UpsertRowGrant(target.group, target.admin.schema, "items", "team", "b"),
                op,
            ],
        )
    assert failure.value.connection == "target"
    assert failure.value.op == op
    assert isinstance(failure.value.original, psycopg.Error)
    assert failure.value.original.sqlstate == ("01006" if revoke else "01007")
    assert failure.value.__cause__ is failure.value.original
    assert removed == opened
    assert all(conn.closed for conn in opened)
    assert await target.snapshot() == before


async def test_actual_filters_acl_grantees_owners_and_scope_but_keeps_orphans(
    apply_target: ApplyTarget,
    superuser_conn: psycopg.AsyncConnection,
    role_factory: Callable[[str], Awaitable[RoleInfo]],
    unique_name: Callable[[str], str],
) -> None:
    target = apply_target
    schema = target.admin.schema
    ignored = await role_factory("gx")
    other_schema = unique_name("outside")
    orphan = unique_name("orphan")
    await superuser_conn.execute(SQL("CREATE SCHEMA {}").format(Identifier(other_schema)))
    await superuser_conn.execute(
        SQL("CREATE TABLE {} (team text)").format(Identifier(other_schema, "outside"))
    )
    await superuser_conn.execute(
        SQL("GRANT SELECT ON {} TO {}").format(
            Identifier(other_schema, "outside"), Identifier(target.group)
        )
    )
    await superuser_conn.execute(
        SQL("ALTER TABLE {} OWNER TO {}").format(
            Identifier(schema, "other"), Identifier(target.user.name)
        )
    )
    await superuser_conn.execute(
        SQL("GRANT SELECT ON {} TO PUBLIC, {}").format(
            Identifier(schema, "items"), Identifier(ignored.name)
        )
    )
    await superuser_conn.execute(
        SQL("GRANT USAGE ON SCHEMA {} TO PUBLIC, {}").format(
            Identifier(schema), Identifier(ignored.name)
        )
    )
    await superuser_conn.execute(
        SQL(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} GRANT SELECT ON TABLES TO {}"
        ).format(Identifier(target.user.name), Identifier(schema), Identifier(target.group))
    )
    await superuser_conn.execute(
        SQL("INSERT INTO gateway_acl.row_grants VALUES ({}, {}, 'gone', 'team', 'b')").format(
            Literal(orphan), Literal(other_schema)
        )
    )
    await target.executor.apply(
        "target",
        [
            GrantTableSelect(schema, "items", target.group),
            GrantSchemaUsage(schema, target.group),
            GrantDefaultSelect(target.admin.login.name, schema, target.group),
            GrantMembership(target.group, ignored.name),
        ],
    )
    state = await target.snapshot()
    assert state.table_select == {(schema, "items", target.group)}
    assert state.schema_usage == {(schema, "gw_managed"), (schema, target.group)}
    assert state.default_select == {(target.admin.login.name, schema, target.group)}
    assert state.row_grants == {(orphan, other_schema, "gone", "team", "b")}
    assert {target.group, target.user.name} <= state.roles
    assert ignored.name not in state.roles
    assert all(row[1] != ignored.name for row in state.memberships)
    async with await target.connect("target") as conn:
        empty = await actual.read_actual(conn, schemas=())
        assert not empty.table_select
        assert not empty.schema_usage
        assert not empty.default_select
        assert not empty.policies
        assert not empty.row_security
        assert empty.roles == state.roles
        assert empty.memberships == state.memberships
        assert empty.row_grants == state.row_grants
        unowned = await actual.read_actual(conn, schemas=(schema,))
        assert not unowned.default_select
        async with conn.transaction():
            with pytest.raises(ValueError, match="idle connection"):
                await actual.read_actual(conn, schemas=(schema,))


async def test_schema_reader_default_select_covers_new_tables_and_revokes(
    apply_target: ApplyTarget,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
) -> None:
    target = apply_target
    rule = target.rule("schema")
    await target.executor.apply(
        "target",
        [GrantMembership(target.group, target.user.name)]
        + [item.op for item in grant_ops(rule, target.context)],
    )
    async with await target.connect("target") as conn:
        await conn.execute(
            SQL("CREATE TABLE {} (team text)").format(Identifier(target.admin.schema, "future"))
        )
        await conn.execute(
            SQL("INSERT INTO {} VALUES ('new')").format(Identifier(target.admin.schema, "future"))
        )
    assert (target.admin.schema, "future", target.group) in (await target.snapshot()).table_select
    query = SQL("SELECT team FROM {}").format(Identifier(target.admin.schema, "future"))
    async with await connect_as(target.user) as conn:
        cursor = await conn.execute(query)
        assert await cursor.fetchall() == [("new",)]
        await target.executor.apply(
            "target", [item.op for item in revoke_ops(rule, target.context)]
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await conn.execute(query)
    assert not (await target.snapshot()).default_select
