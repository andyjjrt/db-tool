"""Catalog scan for owner-privilege objects, through a non-superuser admin (plan §5, §11)."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import LiteralString

import psycopg
import pytest
import pytest_asyncio
from psycopg.sql import SQL, Composable, Identifier, Literal

from db_gateway.permissions.executor import PgExecutor
from db_gateway.permissions.scan import (
    DefinerFunction,
    UnsafeView,
    definer_functions,
    unsafe_views,
)
from db_gateway.permissions.types import (
    CreateGroupRole,
    EnableRowPolicy,
    GrantMembership,
    PgOp,
    UpsertRowGrant,
    user_role,
)
from tests.conftest import PG_USER, RoleInfo
from tests.integration.test_target_db import TargetAdmin
from tests.integration.test_target_db import target_admin as target_admin

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def conn(
    target_admin: TargetAdmin,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
) -> AsyncIterator[psycopg.AsyncConnection]:
    async with await connect_as(target_admin.login) as connection:
        await connection.set_autocommit(True)
        yield connection


async def run(conn: psycopg.AsyncConnection, statement: LiteralString, *params: Composable) -> None:
    await conn.execute(SQL(statement).format(*params))


async def own_by_superuser(
    superuser_conn: psycopg.AsyncConnection, schema: str, *views: str
) -> None:
    for view in views:
        await superuser_conn.execute(
            SQL("ALTER TABLE {} OWNER TO {}").format(Identifier(schema, view), Identifier(PG_USER))
        )


def names(found: list[UnsafeView]) -> list[tuple[str, str]]:
    return [(v.schema, v.name) for v in found]


async def test_plain_view_found_invoker_and_uncontrolled_not(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
) -> None:
    s = target_admin.schema
    t, other = Identifier(s, "t"), Identifier(s, "other")
    await run(conn, "CREATE TABLE {} (a int)", t)
    await run(conn, "CREATE TABLE {} (a int)", other)
    await run(conn, "CREATE VIEW {} AS SELECT a FROM {}", Identifier(s, "plain"), t)
    await run(
        conn,
        "CREATE VIEW {} WITH (security_invoker = true) AS SELECT a FROM {}",
        Identifier(s, "invoker"),
        t,
    )
    await run(
        conn,
        "CREATE VIEW {} WITH (security_invoker = on) AS SELECT a FROM {}",
        Identifier(s, "invoker_on"),
        t,
    )
    await run(
        conn,
        "CREATE VIEW {} WITH (security_invoker = false) AS SELECT a FROM {}",
        Identifier(s, "invoker_off"),
        t,
    )
    await run(conn, "CREATE VIEW {} AS SELECT a FROM {}", Identifier(s, "unrelated"), other)

    # Owned by a plain (non-bypass) admin: RLS still applies, nothing leaks.
    assert await unsafe_views(conn, [(s, "t")]) == []
    assert await unsafe_views(conn, []) == []
    assert await unsafe_views(conn, [(s, "missing")]) == []

    # The same views owned by a superuser: only the non-invoker ones leak.
    await own_by_superuser(
        superuser_conn, s, "plain", "invoker", "invoker_on", "invoker_off", "unrelated"
    )
    found = await unsafe_views(conn, [(s, "t")])
    assert found == [
        UnsafeView(s, "invoker_off", "view", PG_USER, ((s, "t"),), "bypass_owner"),
        UnsafeView(s, "plain", "view", PG_USER, ((s, "t"),), "bypass_owner"),
    ]


@pytest.mark.parametrize(
    "spelling", ["true", "TRUE", "on", "On", "1", "yes", "y", "t", "tr", "'true'", "'ON'"]
)
async def test_boolean_spellings_of_security_invoker(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
    spelling: str,
) -> None:
    s = target_admin.schema
    await run(conn, "CREATE TABLE {} (a int)", Identifier(s, "t"))
    await conn.execute(
        SQL("CREATE VIEW {} WITH (security_invoker = {}, security_barrier = false) AS ").format(
            Identifier(s, "v"),
            SQL(spelling),  # pyright: ignore[reportArgumentType]
        )
        + SQL("SELECT a FROM {}").format(Identifier(s, "t"))
    )
    await own_by_superuser(superuser_conn, s, "v")
    assert await unsafe_views(conn, [(s, "t")]) == []
    await superuser_conn.execute(
        SQL("ALTER VIEW {} SET (security_invoker = false)").format(Identifier(s, "v"))
    )
    assert names(await unsafe_views(conn, [(s, "t")])) == [(s, "v")]


@dataclass(frozen=True, slots=True)
class Rls:
    """Controlled table ``items`` (rows a, b, c); ``reader`` may see only ``b``."""

    admin: TargetAdmin
    reader: RoleInfo
    connect: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]]
    executor: PgExecutor
    group: str

    async def control(self, *tables: str) -> None:
        """Enable the gateway's policies on tables and grant the group row ``b``."""
        s = self.admin.schema
        ops: list[PgOp] = []
        for table in tables:
            ops += [
                EnableRowPolicy(s, table, "team"),
                UpsertRowGrant(self.group, s, table, "team", "b"),
            ]
        await self.executor.apply("target", ops)

    async def seen(self, relation: str) -> list[str]:
        async with await self.connect(self.reader) as reader:
            cursor = await reader.execute(
                SQL("SELECT team FROM {} ORDER BY 1").format(
                    Identifier(self.admin.schema, relation)
                )
            )
            return [row[0] for row in await cursor.fetchall()]

    async def expose(self, owner_conn: psycopg.AsyncConnection, *relations: str) -> None:
        for relation in relations:
            await owner_conn.execute(
                SQL("GRANT SELECT ON {} TO gw_managed").format(
                    Identifier(self.admin.schema, relation)
                )
            )


@pytest_asyncio.fixture
async def rls(
    conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    unique_name: Callable[[str], str],
) -> Rls:
    s = target_admin.schema

    async def connect(role: RoleInfo) -> psycopg.AsyncConnection:
        return await connect_as(role)

    executor = PgExecutor(lambda _name: connect(target_admin.login))
    group = unique_name("g")
    await executor.apply("target", [CreateGroupRole(group)])
    user_id = secrets.randbits(48)
    reader = RoleInfo(user_role(user_id), "scan-test-password")
    await conn.execute(
        SQL("CREATE ROLE {} LOGIN INHERIT PASSWORD {}").format(
            Identifier(reader.name), Literal(reader.password)
        )
    )
    await conn.execute(
        SQL("GRANT gw_managed TO {} WITH INHERIT TRUE").format(Identifier(reader.name))
    )
    await run(conn, "CREATE TABLE {} (team text NOT NULL)", Identifier(s, "items"))
    await run(conn, "INSERT INTO {} VALUES ('a'), ('b'), ('c')", Identifier(s, "items"))
    await executor.apply("target", [GrantMembership(group, reader.name)])
    result = Rls(target_admin, reader, connect_as, executor, group)
    await result.control("items")
    return result


async def test_normal_view_of_plain_owner_does_not_leak(
    conn: psycopg.AsyncConnection, target_admin: TargetAdmin, rls: Rls
) -> None:
    s = target_admin.schema
    await run(
        conn, "CREATE VIEW {} AS SELECT team FROM {}", Identifier(s, "v"), Identifier(s, "items")
    )
    await rls.expose(conn, "v")
    assert await rls.seen("items") == ["b"]
    assert await rls.seen("v") == ["b"]
    assert await unsafe_views(conn, [(s, "items")]) == []


@pytest.mark.parametrize("bypass", ["superuser", "bypassrls"])
async def test_bypass_owner_view_leaks_and_wrappers_follow(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
    rls: Rls,
    role_factory: Callable[[str], Awaitable[RoleInfo]],
    bypass: str,
) -> None:
    s = target_admin.schema
    items = Identifier(s, "items")
    if bypass == "superuser":
        owner = PG_USER
    else:
        owner = (await role_factory("bypass")).name
        await superuser_conn.execute(SQL("ALTER ROLE {} BYPASSRLS").format(Identifier(owner)))
        await superuser_conn.execute(
            SQL("GRANT SELECT ON {} TO {}").format(items, Identifier(owner))
        )
        await superuser_conn.execute(
            SQL("GRANT USAGE ON SCHEMA {} TO {}").format(Identifier(s), Identifier(owner))
        )
        await superuser_conn.execute(
            SQL("GRANT CREATE ON SCHEMA {} TO {}").format(Identifier(s), Identifier(owner))
        )
    leak = Identifier(s, "leak")
    await superuser_conn.execute(SQL("SET ROLE {}").format(Identifier(owner)))
    await superuser_conn.execute(SQL("CREATE VIEW {} AS SELECT team FROM {}").format(leak, items))
    await superuser_conn.execute(
        SQL("GRANT SELECT ON {} TO gw_managed, {}").format(
            leak, Identifier(target_admin.login.name)
        )
    )
    await superuser_conn.execute("RESET ROLE")
    await run(
        conn,
        "CREATE VIEW {} WITH (security_invoker = true) AS SELECT team FROM {}",
        Identifier(s, "wrapper"),
        leak,
    )
    await run(conn, "CREATE VIEW {} AS SELECT team FROM {}", Identifier(s, "outer_plain"), leak)
    await rls.expose(conn, "wrapper", "outer_plain")

    assert await rls.seen("items") == ["b"]
    assert await rls.seen("leak") == ["a", "b", "c"]
    assert await rls.seen("wrapper") == ["a", "b", "c"]
    assert await rls.seen("outer_plain") == ["a", "b", "c"]
    found = {v.name: v for v in await unsafe_views(conn, [(s, "items")])}
    assert set(found) == {"leak", "wrapper", "outer_plain"}
    assert found["leak"] == UnsafeView(s, "leak", "view", owner, ((s, "items"),), "bypass_owner")
    assert all(v.reads == ((s, "items"),) for v in found.values())
    assert all(v.reason == "bypass_owner" for v in found.values())


async def test_bypass_owner_over_invoker_view_does_not_leak(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
    rls: Rls,
) -> None:
    s = target_admin.schema
    await run(
        conn,
        "CREATE VIEW {} WITH (security_invoker = true) AS SELECT team FROM {}",
        Identifier(s, "inner_v"),
        Identifier(s, "items"),
    )
    await superuser_conn.execute(
        SQL("CREATE VIEW {} AS SELECT team FROM {}").format(
            Identifier(s, "outer_v"), Identifier(s, "inner_v")
        )
    )
    await superuser_conn.execute(
        SQL("GRANT SELECT ON {} TO gw_managed").format(Identifier(s, "outer_v"))
    )
    await rls.expose(conn, "inner_v")
    assert await rls.seen("inner_v") == ["b"]
    assert await rls.seen("outer_v") == ["b"]
    assert await unsafe_views(conn, [(s, "items")]) == []


async def test_matviews_leak_and_wrappers_follow(
    conn: psycopg.AsyncConnection, target_admin: TargetAdmin, rls: Rls
) -> None:
    s = target_admin.schema
    items = Identifier(s, "items")
    # Refreshed by the admin session (policy gw_passthrough lets it see all rows).
    await run(
        conn, "CREATE MATERIALIZED VIEW {} AS SELECT team FROM {}", Identifier(s, "mv"), items
    )
    await run(
        conn,
        "CREATE VIEW {} WITH (security_invoker = true) AS SELECT team FROM {}",
        Identifier(s, "inv_over_mv"),
        Identifier(s, "mv"),
    )
    await rls.expose(conn, "mv", "inv_over_mv")
    assert await rls.seen("mv") == ["a", "b", "c"]
    assert await rls.seen("inv_over_mv") == ["a", "b", "c"]
    found = {v.name: v for v in await unsafe_views(conn, [(s, "items")])}
    assert set(found) == {"mv", "inv_over_mv"}
    assert found["mv"] == UnsafeView(
        s, "mv", "matview", target_admin.login.name, ((s, "items"),), "matview"
    )
    assert found["inv_over_mv"].kind == "view"
    assert all(v.reason == "matview" and v.reads == ((s, "items"),) for v in found.values())


async def test_matview_through_a_view_chain_leaks(
    conn: psycopg.AsyncConnection, target_admin: TargetAdmin
) -> None:
    s = target_admin.schema
    await run(conn, "CREATE TABLE {} (a int)", Identifier(s, "t1"))
    await run(conn, "CREATE TABLE {} (a int)", Identifier(s, "t2"))
    await run(
        conn,
        "CREATE VIEW {} WITH (security_invoker = true) AS SELECT a FROM {}",
        Identifier(s, "inv"),
        Identifier(s, "t1"),
    )
    await run(
        conn,
        "CREATE MATERIALIZED VIEW {} AS SELECT x.a FROM {} x JOIN {} y ON x.a = y.a",
        Identifier(s, "mv"),
        Identifier(s, "inv"),
        Identifier(s, "t2"),
    )
    found = await unsafe_views(conn, [(s, "t2"), (s, "t1")])
    assert [(v.name, v.reads) for v in found] == [("mv", ((s, "t1"), (s, "t2")))]
    assert await unsafe_views(conn, [(s, "t1")]) == [
        UnsafeView(s, "mv", "matview", target_admin.login.name, ((s, "t1"),), "matview")
    ]


QUERY_SHAPES = {
    "subquery": "SELECT a FROM (SELECT a FROM {t}) q",
    "cte": "WITH c AS (SELECT a FROM {t}) SELECT a FROM c",
    "lateral": "SELECT o.a FROM {o} o, LATERAL (SELECT 1 FROM {t} x WHERE x.a = o.a) l",
    "union": "SELECT a FROM {o} UNION SELECT a FROM {t}",
    "intersect": "SELECT a FROM {o} INTERSECT SELECT a FROM {t}",
    "except": "SELECT a FROM {o} EXCEPT SELECT a FROM {t}",
    "exists": "SELECT a FROM {o} o WHERE EXISTS (SELECT 1 FROM {t} x WHERE x.a = o.a)",
    "scalar": "SELECT (SELECT max(a) FROM {t}) AS a",
}


@pytest.mark.parametrize("shape", QUERY_SHAPES)
async def test_query_shapes(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
    shape: str,
) -> None:
    s = target_admin.schema
    await run(conn, "CREATE TABLE {} (a int)", Identifier(s, "t"))
    await run(conn, "CREATE TABLE {} (a int)", Identifier(s, "o"))
    query = SQL(QUERY_SHAPES[shape]).format(t=Identifier(s, "t"), o=Identifier(s, "o"))  # pyright: ignore[reportArgumentType]
    await conn.execute(SQL("CREATE VIEW {} AS {}").format(Identifier(s, "v"), query))
    await own_by_superuser(superuser_conn, s, "v")
    found = await unsafe_views(conn, [(s, "t")])
    assert [(v.name, v.reads) for v in found] == [("v", ((s, "t"),))]


async def test_view_in_another_schema(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
    unique_name: Callable[[str], str],
) -> None:
    s = target_admin.schema
    other = unique_name("other")
    await run(conn, "CREATE SCHEMA {}", Identifier(other))
    await run(conn, "CREATE TABLE {} (a int)", Identifier(s, "t"))
    await run(
        conn, "CREATE VIEW {} AS SELECT a FROM {}", Identifier(other, "v"), Identifier(s, "t")
    )
    await own_by_superuser(superuser_conn, other, "v")
    assert names(await unsafe_views(conn, [(s, "t")])) == [(other, "v")]


async def test_partitions_count_in_both_directions(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
) -> None:
    """Structural: catalog traversal only (empty tables, superuser-owned views).

    A controlled table stands for its partition tree: its descendants and ancestors.
    Row-level exposure is covered by the *_row_oracle tests below.
    Siblings of a controlled partition are not part of it.
    """
    s = target_admin.schema
    parent, mid, leaf, sibling = (Identifier(s, n) for n in ("parent", "mid", "leaf", "sibling"))
    await run(conn, "CREATE TABLE {} (a int, b int) PARTITION BY RANGE (a)", parent)
    await run(
        conn,
        "CREATE TABLE {} PARTITION OF {} FOR VALUES FROM (0) TO (10) PARTITION BY RANGE (b)",
        mid,
        parent,
    )
    await run(conn, "CREATE TABLE {} PARTITION OF {} FOR VALUES FROM (0) TO (5)", leaf, mid)
    await run(conn, "CREATE TABLE {} PARTITION OF {} FOR VALUES FROM (10) TO (20)", sibling, parent)
    for view, table in (("v_parent", parent), ("v_mid", mid), ("v_leaf", leaf), ("v_sib", sibling)):
        await run(conn, "CREATE VIEW {} AS SELECT a FROM {}", Identifier(s, view), table)
        await own_by_superuser(superuser_conn, s, view)

    # Controlled parent: every partition under it counts.
    assert names(await unsafe_views(conn, [(s, "parent")])) == [
        (s, "v_leaf"),
        (s, "v_mid"),
        (s, "v_parent"),
        (s, "v_sib"),
    ]
    # Controlled middle partition: itself, its leaf, and its ancestor; not its sibling.
    found = await unsafe_views(conn, [(s, "mid")])
    assert names(found) == [(s, "v_leaf"), (s, "v_mid"), (s, "v_parent")]
    assert all(v.reads == ((s, "mid"),) for v in found)
    # Controlled leaf: itself and its ancestors.
    assert names(await unsafe_views(conn, [(s, "leaf")])) == [
        (s, "v_leaf"),
        (s, "v_mid"),
        (s, "v_parent"),
    ]


async def test_definer_functions(conn: psycopg.AsyncConnection, target_admin: TargetAdmin) -> None:
    s = target_admin.schema
    owner = target_admin.login.name
    await run(
        conn,
        "CREATE FUNCTION {}(x int) RETURNS int LANGUAGE sql SECURITY DEFINER "
        "SET search_path = pg_catalog AS 'SELECT x'",
        Identifier(s, "definer_fn"),
    )
    await run(
        conn,
        "CREATE FUNCTION {}(x int) RETURNS int LANGUAGE sql AS 'SELECT x'",
        Identifier(s, "invoker_fn"),
    )
    await run(
        conn,
        "CREATE PROCEDURE {}() LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
        Identifier(s, "definer_proc"),
    )
    found = [f for f in await definer_functions(conn) if f.schema == s]
    assert found == [
        DefinerFunction(s, "definer_fn", "x integer", owner, True, False),
        DefinerFunction(s, "definer_proc", "", owner, True, False),
    ]
    # gateway_acl.* are SECURITY DEFINER but never listed.
    assert all(f.schema != "gateway_acl" for f in await definer_functions(conn))

    await run(conn, "REVOKE EXECUTE ON FUNCTION {}(int) FROM PUBLIC", Identifier(s, "definer_fn"))
    found = [f for f in await definer_functions(conn) if f.schema == s]
    assert [(f.name, f.executable_by_managed) for f in found] == [
        ("definer_fn", False),
        ("definer_proc", True),
    ]
    await run(conn, "GRANT EXECUTE ON FUNCTION {}(int) TO gw_managed", Identifier(s, "definer_fn"))
    found = [f for f in await definer_functions(conn) if f.schema == s]
    assert [(f.name, f.executable_by_managed) for f in found][0] == ("definer_fn", True)


async def test_extension_function_not_listed(
    conn: psycopg.AsyncConnection, target_admin: TargetAdmin
) -> None:
    s = target_admin.schema
    await run(conn, "CREATE EXTENSION pgcrypto SCHEMA {}", Identifier(s))
    await run(
        conn,
        "CREATE FUNCTION {}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
        Identifier(s, "ext_fn"),
    )
    assert [f.name for f in await definer_functions(conn) if f.schema == s] == ["ext_fn"]
    await run(conn, "ALTER EXTENSION pgcrypto ADD FUNCTION {}()", Identifier(s, "ext_fn"))
    assert [f for f in await definer_functions(conn) if f.schema == s] == []
    await run(conn, "ALTER EXTENSION pgcrypto DROP FUNCTION {}()", Identifier(s, "ext_fn"))
    await run(conn, "DROP EXTENSION pgcrypto")


async def test_search_path_shadowing_does_not_change_results(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
) -> None:
    s = target_admin.schema
    await run(conn, "CREATE TABLE {} (a int)", Identifier(s, "t"))
    await run(conn, "CREATE VIEW {} AS SELECT a FROM {}", Identifier(s, "v"), Identifier(s, "t"))
    await own_by_superuser(superuser_conn, s, "v")
    await run(
        conn,
        "CREATE FUNCTION {}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
        Identifier(s, "fn"),
    )
    expected_views = await unsafe_views(conn, [(s, "t")])
    expected_fns = await definer_functions(conn)
    assert names(expected_views) == [(s, "v")]

    # Shadow catalog relations and an operator; the scan must not resolve to them.
    for relation in ("pg_depend", "pg_rewrite", "pg_inherits", "pg_class", "pg_proc", "pg_roles"):
        await run(conn, "CREATE TABLE {} (x int)", Identifier(s, relation))
    await run(
        conn,
        "CREATE FUNCTION {}(text, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
        Identifier(s, "shadow_eq"),
    )
    await run(
        conn,
        "CREATE OPERATOR {}.= (LEFTARG = text, RIGHTARG = text, FUNCTION = {})",
        Identifier(s),
        Identifier(s, "shadow_eq"),
    )
    await run(conn, "SET search_path = {}, pg_catalog", Identifier(s))
    assert await unsafe_views(conn, [(s, "t")]) == expected_views
    assert await definer_functions(conn) == expected_fns


async def test_definer_function_owner_bypass_flag(
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
    conn: psycopg.AsyncConnection,
) -> None:
    s = target_admin.schema
    await superuser_conn.execute(
        SQL(
            "CREATE FUNCTION {}() RETURNS int LANGUAGE sql SECURITY DEFINER "
            "SET search_path = pg_catalog AS 'SELECT 1'"
        ).format(Identifier(s, "su_fn"))
    )
    await run(
        conn,
        "CREATE FUNCTION {}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
        Identifier(s, "plain_fn"),
    )
    found = {f.name: f for f in await definer_functions(conn) if f.schema == s}
    assert found["su_fn"].owner == PG_USER
    assert found["su_fn"].owner_bypasses_rls
    assert not found["plain_fn"].owner_bypasses_rls


async def _partitioned_items(conn: psycopg.AsyncConnection, schema: str) -> None:
    await run(
        conn,
        "CREATE TABLE {} (team text NOT NULL) PARTITION BY LIST (team)",
        Identifier(schema, "pitems"),
    )
    await run(
        conn,
        "CREATE TABLE {} PARTITION OF {} DEFAULT",
        Identifier(schema, "pleaf"),
        Identifier(schema, "pitems"),
    )
    await run(conn, "INSERT INTO {} VALUES ('a'), ('b'), ('c')", Identifier(schema, "pitems"))


async def test_partition_entry_points_row_oracle(
    conn: psycopg.AsyncConnection, target_admin: TargetAdmin, rls: Rls
) -> None:
    """Plain-owner views on an uncontrolled family member expose every row."""
    s = target_admin.schema
    await _partitioned_items(conn, s)
    await rls.control("pitems")
    await run(
        conn,
        "CREATE VIEW {} AS SELECT team FROM {}",
        Identifier(s, "on_leaf"),
        Identifier(s, "pleaf"),
    )
    await run(
        conn,
        "CREATE VIEW {} AS SELECT team FROM {}",
        Identifier(s, "on_parent"),
        Identifier(s, "pitems"),
    )
    await run(
        conn,
        "CREATE VIEW {} WITH (security_invoker = true) AS SELECT team FROM {}",
        Identifier(s, "inv_on_leaf"),
        Identifier(s, "pleaf"),
    )
    await run(
        conn,
        "CREATE VIEW {} AS SELECT team FROM {}",
        Identifier(s, "over_leaf"),
        Identifier(s, "on_leaf"),
    )
    await rls.expose(conn, "on_leaf", "on_parent", "inv_on_leaf", "over_leaf")
    assert await rls.seen("on_parent") == ["b"]
    assert await rls.seen("on_leaf") == ["a", "b", "c"]
    assert await rls.seen("over_leaf") == ["a", "b", "c"]
    owner = target_admin.login.name
    found = await unsafe_views(conn, [(s, "pitems")])
    assert found == [
        UnsafeView(s, "on_leaf", "view", owner, ((s, "pitems"),), "unprotected_partition"),
        UnsafeView(s, "over_leaf", "view", owner, ((s, "pitems"),), "unprotected_partition"),
    ]

    # Controlling the leaf as well closes the entry point.
    await rls.control("pleaf")
    assert await rls.seen("on_leaf") == ["b"]
    assert await unsafe_views(conn, [(s, "pitems"), (s, "pleaf")]) == []


async def test_controlled_leaf_with_view_on_parent_row_oracle(
    conn: psycopg.AsyncConnection, target_admin: TargetAdmin, rls: Rls
) -> None:
    s = target_admin.schema
    await _partitioned_items(conn, s)
    await rls.control("pleaf")
    await run(
        conn,
        "CREATE VIEW {} AS SELECT team FROM {}",
        Identifier(s, "on_parent"),
        Identifier(s, "pitems"),
    )
    await run(
        conn,
        "CREATE VIEW {} AS SELECT team FROM {}",
        Identifier(s, "on_leaf"),
        Identifier(s, "pleaf"),
    )
    await rls.expose(conn, "on_parent", "on_leaf")
    assert await rls.seen("on_leaf") == ["b"]
    assert await rls.seen("on_parent") == ["a", "b", "c"]
    found = await unsafe_views(conn, [(s, "pleaf")])
    assert [(v.name, v.reads, v.reason) for v in found] == [
        ("on_parent", ((s, "pleaf"),), "unprotected_partition")
    ]


@pytest.mark.parametrize("variant", ["bypass_definer", "invoker_function", "plain_definer"])
@pytest.mark.parametrize("wrapper", [False, True])
async def test_function_inside_view_row_oracle(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
    rls: Rls,
    variant: str,
    wrapper: bool,
) -> None:
    s = target_admin.schema
    fn = Identifier(s, "fn")
    definer = SQL(
        "SECURITY DEFINER SET search_path = pg_catalog" if variant != "invoker_function" else ""
    )
    create = SQL(
        "CREATE FUNCTION {}() RETURNS SETOF text LANGUAGE sql {} "
        "BEGIN ATOMIC SELECT team FROM {}; END"
    ).format(fn, definer, Identifier(s, "items"))
    await (conn if variant == "plain_definer" else superuser_conn).execute(create)
    await run(conn, "CREATE VIEW {} AS SELECT fn AS team FROM {}()", Identifier(s, "fv"), fn)
    view = "fv"
    if wrapper:
        await run(
            conn,
            "CREATE VIEW {} WITH (security_invoker = true) AS SELECT team FROM {}",
            Identifier(s, "wrap"),
            Identifier(s, "fv"),
        )
        view = "wrap"
    await rls.expose(conn, *(("fv", "wrap") if wrapper else ("fv",)))
    found = await unsafe_views(conn, [(s, "items")])
    if variant == "bypass_definer":
        assert await rls.seen(view) == ["a", "b", "c"]
        assert [(v.name, v.reads, v.reason) for v in found] == [
            (name, (), "bypass_definer_function")
            for name in (["fv", "wrap"] if wrapper else ["fv"])
        ]
    else:
        assert await rls.seen(view) == ["b"]
        assert found == []


@pytest.mark.parametrize("definer", [True, False])
async def test_matview_calling_a_function_row_oracle(
    conn: psycopg.AsyncConnection,
    superuser_conn: psycopg.AsyncConnection,
    target_admin: TargetAdmin,
    rls: Rls,
    definer: bool,
) -> None:
    """A matview filled through any user function holds the refreshing session's rows."""
    s = target_admin.schema
    fn = Identifier(s, "snapshot_source")
    create = SQL(
        "CREATE FUNCTION {}() RETURNS SETOF text LANGUAGE sql {} "
        "BEGIN ATOMIC SELECT team FROM {}; END"
    ).format(
        fn,
        SQL("SECURITY DEFINER SET search_path = pg_catalog" if definer else ""),
        Identifier(s, "items"),
    )
    await (superuser_conn if definer else conn).execute(create)
    await run(
        conn,
        "CREATE MATERIALIZED VIEW {} AS SELECT snapshot_source AS team FROM {}()",
        Identifier(s, "snapshot"),
        fn,
    )
    await run(
        conn,
        "CREATE VIEW {} WITH (security_invoker = true) AS SELECT team FROM {}",
        Identifier(s, "snapshot_wrapper"),
        Identifier(s, "snapshot"),
    )
    await rls.expose(conn, "snapshot", "snapshot_wrapper")
    assert await rls.seen("items") == ["b"]
    assert await rls.seen("snapshot_wrapper") == ["a", "b", "c"]
    found = await unsafe_views(conn, [(s, "items")])
    assert [(v.name, v.kind, v.reason) for v in found] == [
        ("snapshot", "matview", "matview"),
        ("snapshot_wrapper", "view", "matview"),
    ]
