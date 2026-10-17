"""Integration tests for manual target-database setup and read-only checks."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import LiteralString, cast

import psycopg
import pytest
import pytest_asyncio
from psycopg.sql import SQL, Identifier, Literal

from db_gateway.targetdb import Problem, check, check_target_db
from db_gateway.targetdb.check import SETUP_VERSION
from tests.conftest import PG_USER, RoleInfo

pytestmark = pytest.mark.integration

_SETUP_SQL = cast(
    LiteralString, files("db_gateway.targetdb").joinpath("setup.sql").read_text(encoding="utf-8")
)


@dataclass(frozen=True, slots=True)
class TargetAdmin:
    login: RoleInfo
    schema: str


@pytest_asyncio.fixture
async def target_admin(
    target_db: str,
    superuser_conn: psycopg.AsyncConnection,
    role_factory: Callable[[str], Awaitable[RoleInfo]],
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    unique_name: Callable[[str], str],
    cluster_lock: psycopg.AsyncConnection | None,
) -> AsyncIterator[TargetAdmin]:
    """Create a CREATEROLE login that owns the target DB and managed schema."""
    login = await role_factory("targetadmin")
    role_id = Identifier(login.name)
    database_id = Identifier(target_db)
    schema_name = unique_name("managed")

    try:
        await superuser_conn.execute(SQL("ALTER ROLE {} CREATEROLE").format(role_id))
        await superuser_conn.execute(
            SQL("GRANT CREATE ON DATABASE {} TO {}").format(database_id, role_id)
        )
        await superuser_conn.execute(
            SQL("ALTER DATABASE {} OWNER TO {}").format(database_id, role_id)
        )

        cursor = await superuser_conn.execute(
            "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'gw_managed'"
        )
        managed_exists = await cursor.fetchone() is not None
        if managed_exists:
            await superuser_conn.execute(
                SQL("GRANT gw_managed TO {} WITH ADMIN OPTION, INHERIT FALSE, SET FALSE").format(
                    role_id
                )
            )

        async with await connect_as(login) as admin_conn:
            if not managed_exists:
                await admin_conn.execute("CREATE ROLE gw_managed NOLOGIN")
            await admin_conn.execute(
                SQL("CREATE SCHEMA {} AUTHORIZATION CURRENT_USER").format(Identifier(schema_name))
            )
            # setup.sql is deliberately executed only by the integration test, never by src/.
            await admin_conn.execute(SQL(_SETUP_SQL))
            await admin_conn.execute(
                SQL("GRANT USAGE ON SCHEMA {} TO gw_managed").format(Identifier(schema_name))
            )

        superuser_sql = cast(
            LiteralString,
            files("db_gateway.targetdb")
            .joinpath("setup_superuser.sql")
            .read_text(encoding="utf-8"),
        )
        await superuser_conn.execute(SQL(superuser_sql))
        yield TargetAdmin(login=login, schema=schema_name)
    finally:
        # role_factory drops LOGIN roles after this fixture tears down.
        await superuser_conn.execute(
            SQL("ALTER DATABASE {} OWNER TO {}").format(database_id, Identifier(PG_USER))
        )


async def _catalog_snapshot(conn: psycopg.AsyncConnection) -> tuple[object, ...]:
    cursor = await conn.execute(
        "SELECT "
        "  (SELECT datacl::text FROM pg_catalog.pg_database "
        "   WHERE datname = pg_catalog.current_database()), "
        "  (SELECT array_agg(nspname || ':' || coalesce(nspacl::text, '') ORDER BY nspname) "
        "   FROM pg_catalog.pg_namespace "
        "   WHERE nspname IN ('gateway_acl', 'paradedb')), "
        "  (SELECT array_agg(relname || ':' || coalesce(relacl::text, '') ORDER BY relname) "
        "   FROM pg_catalog.pg_class "
        "   WHERE relnamespace = pg_catalog.to_regnamespace('gateway_acl')), "
        "  (SELECT array_agg(proname || ':' || prosrc || ':' || "
        "                    coalesce(proconfig::text, '') ORDER BY proname) "
        "   FROM pg_catalog.pg_proc "
        "   WHERE pronamespace = pg_catalog.to_regnamespace('gateway_acl')), "
        "  (SELECT array_agg(version ORDER BY singleton) "
        "   FROM gateway_acl.setup_version), "
        "  (SELECT count(*) FROM gateway_acl.row_grants)"
    )
    row = await cursor.fetchone()
    assert row is not None
    return row


async def _check_without_changes(
    *,
    superuser_conn: psycopg.AsyncConnection,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    admin: TargetAdmin,
    schemas: Sequence[str] | None = None,
    default_privilege_owners: Sequence[str] = (),
) -> list[Problem]:
    before = await _catalog_snapshot(superuser_conn)
    async with await connect_as(admin.login) as conn:
        cursor = await conn.execute(
            "SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user"
        )
        assert await cursor.fetchone() == (False,)
        problems = await check_target_db(
            conn,
            schemas=(admin.schema,) if schemas is None else schemas,
            default_privilege_owners=default_privilege_owners,
        )
    after = await _catalog_snapshot(superuser_conn)
    assert after == before
    return problems


async def test_check_clean_setup_is_read_only(
    superuser_conn: psycopg.AsyncConnection,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    target_admin: TargetAdmin,
) -> None:
    assert (
        await _check_without_changes(
            superuser_conn=superuser_conn, connect_as=connect_as, admin=target_admin
        )
        == []
    )


def test_setup_version_sources_agree() -> None:
    version_comment = re.search(r"(?m)^-- setup_version: (\d+)$", _SETUP_SQL)
    version_guard = re.search(r"current_version\s*>\s*(\d+)", _SETUP_SQL)
    version_marker = re.search(r"VALUES\s*\(\s*TRUE\s*,\s*(\d+)\s*\)", _SETUP_SQL)

    assert version_comment is not None
    assert version_guard is not None
    assert version_marker is not None
    assert {
        SETUP_VERSION,
        int(version_comment.group(1)),
        int(version_guard.group(1)),
        int(version_marker.group(1)),
    } == {1}


async def test_check_rejects_an_open_transaction(
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    target_admin: TargetAdmin,
) -> None:
    async with await connect_as(target_admin.login) as conn:
        async with conn.transaction():
            await conn.execute("SELECT 1")
            with pytest.raises(ValueError, match="requires an idle connection"):
                await check_target_db(
                    conn, schemas=(target_admin.schema,), default_privilege_owners=()
                )
            cursor = await conn.execute("SHOW transaction_read_only")
            assert await cursor.fetchone() == ("off",)


@pytest.mark.parametrize(
    ("defect", "expected_code"),
    [
        ("drop_function", "function_missing"),
        ("alter_function_body", "function_body_mismatch"),
        ("grant_row_grants", "row_grants_public_privilege"),
        ("revoke_schema_usage", "managed_schema_usage"),
        ("remove_createrole", "admin_privileges"),
        ("stale_version", "setup_version_outdated"),
        ("superuser_owned_setup", "row_grants_admin_privilege"),
        ("function_owner_cannot_read", "function_row_grants_access"),
        ("function_overload", "function_overload"),
        ("gateway_acl_create_grant", "gateway_acl_extra_create"),
        ("function_not_sql", "function_language"),
        ("admin_is_managed", "admin_is_managed"),
    ],
)
async def test_check_reports_each_broken_setup_item(
    defect: str,
    expected_code: str,
    target_db: str,
    superuser_conn: psycopg.AsyncConnection,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    target_admin: TargetAdmin,
    unique_name: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if defect == "drop_function":
        await superuser_conn.execute("DROP FUNCTION gateway_acl.allowed_values(name, name)")
    elif defect == "alter_function_body":
        await superuser_conn.execute(
            "CREATE OR REPLACE FUNCTION gateway_acl.is_managed() RETURNS boolean "
            "LANGUAGE sql STABLE SECURITY DEFINER "
            "SET search_path = pg_catalog, pg_temp "
            "AS $$ SELECT FALSE $$"
        )
    elif defect == "grant_row_grants":
        await superuser_conn.execute("GRANT SELECT ON gateway_acl.row_grants TO PUBLIC")
    elif defect == "revoke_schema_usage":
        await superuser_conn.execute(
            SQL("REVOKE USAGE ON SCHEMA {} FROM gw_managed").format(Identifier(target_admin.schema))
        )
    elif defect == "remove_createrole":
        await superuser_conn.execute(
            SQL("ALTER ROLE {} NOCREATEROLE").format(Identifier(target_admin.login.name))
        )
    elif defect == "stale_version":
        # The DB stays at the current version; the gateway now expects a newer one.
        monkeypatch.setattr(check, "SETUP_VERSION", SETUP_VERSION + 1)
    elif defect == "superuser_owned_setup":
        await superuser_conn.execute("ALTER SCHEMA gateway_acl OWNER TO CURRENT_USER")
        await superuser_conn.execute("ALTER TABLE gateway_acl.row_grants OWNER TO CURRENT_USER")
        await superuser_conn.execute("ALTER TABLE gateway_acl.setup_version OWNER TO CURRENT_USER")
        await superuser_conn.execute(
            "ALTER FUNCTION gateway_acl.is_managed() OWNER TO CURRENT_USER"
        )
        await superuser_conn.execute(
            "ALTER FUNCTION gateway_acl.allow_all(name, name) OWNER TO CURRENT_USER"
        )
        await superuser_conn.execute(
            "ALTER FUNCTION gateway_acl.allowed_values(name, name) OWNER TO CURRENT_USER"
        )
        await superuser_conn.execute(
            SQL("REVOKE ALL ON TABLE gateway_acl.row_grants FROM {}").format(
                Identifier(target_admin.login.name)
            )
        )
    elif defect == "function_owner_cannot_read":
        function_owner = unique_name("fnowner")
        await superuser_conn.execute(
            SQL("CREATE ROLE {} NOLOGIN").format(Identifier(function_owner))
        )
        await superuser_conn.execute(
            SQL("GRANT CREATE ON SCHEMA gateway_acl TO {}").format(Identifier(function_owner))
        )
        await superuser_conn.execute(
            SQL("ALTER FUNCTION gateway_acl.allow_all(name, name) OWNER TO {}").format(
                Identifier(function_owner)
            )
        )
        await superuser_conn.execute(
            SQL("REVOKE CREATE ON SCHEMA gateway_acl FROM {}").format(Identifier(function_owner))
        )
    elif defect == "function_overload":
        await superuser_conn.execute(
            "CREATE FUNCTION gateway_acl.allow_all(text, text) RETURNS boolean "
            "LANGUAGE sql STABLE SECURITY DEFINER "
            "SET search_path = pg_catalog, pg_temp AS $$ SELECT TRUE $$"
        )
    elif defect == "gateway_acl_create_grant":
        extra_creator = unique_name("aclcreate")
        await superuser_conn.execute(
            SQL("CREATE ROLE {} NOLOGIN").format(Identifier(extra_creator))
        )
        await superuser_conn.execute(
            SQL("GRANT CREATE ON SCHEMA gateway_acl TO {}").format(Identifier(extra_creator))
        )
    elif defect == "function_not_sql":
        await superuser_conn.execute("DROP FUNCTION gateway_acl.is_managed()")
        await superuser_conn.execute(
            "CREATE FUNCTION gateway_acl.is_managed() RETURNS boolean "
            "LANGUAGE plpgsql STABLE SECURITY DEFINER "
            "SET search_path = pg_catalog, pg_temp "
            "AS $$ BEGIN RETURN FALSE; END $$"
        )
    elif defect == "admin_is_managed":
        await superuser_conn.execute(
            SQL("GRANT gw_managed TO {} WITH INHERIT TRUE").format(
                Identifier(target_admin.login.name)
            )
        )
    else:
        pytest.fail(f"unknown test defect: {defect}")

    problems = await _check_without_changes(
        superuser_conn=superuser_conn, connect_as=connect_as, admin=target_admin
    )
    assert expected_code in {problem.code for problem in problems}


async def test_check_reports_createrole_self_grant_setting(
    superuser_conn: psycopg.AsyncConnection,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    target_admin: TargetAdmin,
) -> None:
    before = await _catalog_snapshot(superuser_conn)
    async with await connect_as(target_admin.login) as conn:
        await conn.execute("SET createrole_self_grant = 'set, inherit'")
        problems = await check_target_db(
            conn, schemas=(target_admin.schema,), default_privilege_owners=()
        )
    assert "createrole_self_grant" in {problem.code for problem in problems}
    assert await _catalog_snapshot(superuser_conn) == before


async def test_ordinary_role_cannot_read_row_grants(
    role_factory: Callable[[str], Awaitable[RoleInfo]],
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    target_admin: TargetAdmin,
) -> None:
    ordinary = await role_factory("ordinary")
    async with await connect_as(ordinary) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await conn.execute("SELECT * FROM gateway_acl.row_grants")


async def test_rls_session_user_policy_orphans_and_hijack_protection(
    target_db: str,
    superuser_conn: psycopg.AsyncConnection,
    role_factory: Callable[[str], Awaitable[RoleInfo]],
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    target_admin: TargetAdmin,
    unique_name: Callable[[str], str],
) -> None:
    table_name = unique_name("rows")
    groups = {
        "all": unique_name("gall"),
        "a": unique_name("ga"),
        "b": unique_name("gb"),
    }
    users = {
        "all": await role_factory("userall"),
        "a": await role_factory("usera"),
        "b": await role_factory("userb"),
        "none": await role_factory("usernone"),
        "noinherit": await role_factory("usernoinherit"),
        "app": await role_factory("unmanaged"),
    }

    for group_name in groups.values():
        await superuser_conn.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(group_name)))
        await superuser_conn.execute(SQL("GRANT gw_managed TO {}").format(Identifier(group_name)))

    for key in ("all", "a", "b", "none"):
        await superuser_conn.execute(
            SQL("GRANT gw_managed TO {}").format(Identifier(users[key].name))
        )
    await superuser_conn.execute(
        SQL("ALTER ROLE {} NOINHERIT").format(Identifier(users["noinherit"].name))
    )
    await superuser_conn.execute(
        SQL("GRANT gw_managed TO {}").format(Identifier(users["noinherit"].name))
    )
    for key in ("all", "a", "b"):
        await superuser_conn.execute(
            SQL("GRANT {} TO {}").format(Identifier(groups[key]), Identifier(users[key].name))
        )

    schema_id = Identifier(target_admin.schema)
    table_id = Identifier(table_name)
    async with await connect_as(target_admin.login) as admin_conn:
        async with admin_conn.transaction():
            await admin_conn.execute(
                SQL("CREATE TABLE {}.{} (team text NOT NULL)").format(schema_id, table_id)
            )
            await admin_conn.execute(
                SQL("ALTER TABLE {}.{} ENABLE ROW LEVEL SECURITY").format(schema_id, table_id)
            )
            await admin_conn.execute(
                SQL("ALTER TABLE {}.{} FORCE ROW LEVEL SECURITY").format(schema_id, table_id)
            )
            await admin_conn.execute(
                SQL(
                    "CREATE POLICY gw_passthrough ON {}.{} "
                    "USING (NOT (SELECT gateway_acl.is_managed()))"
                ).format(schema_id, table_id)
            )
            await admin_conn.execute(
                SQL(
                    "CREATE POLICY gw_read ON {}.{} FOR SELECT "
                    "USING ((SELECT gateway_acl.allow_all({}, {})) "
                    "OR team::text = ANY "
                    "((SELECT gateway_acl.allowed_values({}, {}))::text[]))"
                ).format(
                    schema_id,
                    table_id,
                    Literal(target_admin.schema),
                    Literal(table_name),
                    Literal(target_admin.schema),
                    Literal(table_name),
                )
            )
            await admin_conn.execute(
                SQL("GRANT SELECT ON {}.{} TO gw_managed").format(schema_id, table_id)
            )

    await superuser_conn.execute(
        SQL("INSERT INTO {}.{} (team) VALUES ('a'), ('b'), ('c')").format(schema_id, table_id)
    )

    creator_group = unique_name("gcreator")
    async with await connect_as(target_admin.login) as admin_conn:
        await admin_conn.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(creator_group)))
        cursor = await admin_conn.execute(
            "SELECT pg_catalog.pg_has_role(session_user, 'gw_managed', 'MEMBER'), "
            "pg_catalog.pg_has_role(session_user, 'gw_managed', 'USAGE'), "
            "pg_catalog.pg_has_role(session_user, 'gw_managed', 'SET'), "
            "gateway_acl.is_managed()"
        )
        assert await cursor.fetchone() == (True, False, False, False)
        cursor = await admin_conn.execute(
            "SELECT pg_catalog.pg_has_role(session_user, %s, 'MEMBER'), "
            "pg_catalog.pg_has_role(session_user, %s, 'USAGE'), "
            "pg_catalog.pg_has_role(session_user, %s, 'SET')",
            (creator_group, creator_group, creator_group),
        )
        assert await cursor.fetchone() == (True, False, False)

    orphan_group = unique_name("orphan")
    for grant in (
        (groups["all"], target_admin.schema, table_name, "*", "*"),
        (groups["a"], target_admin.schema, table_name, "*", "a"),
        (groups["b"], target_admin.schema, table_name, "*", "b"),
        (creator_group, target_admin.schema, table_name, "*", "b"),
        (orphan_group, target_admin.schema, table_name, "*", "c"),
    ):
        await superuser_conn.execute(
            "INSERT INTO gateway_acl.row_grants "
            "(group_role, schema_name, table_name, column_name, value) "
            "VALUES (%s, %s, %s, %s, %s)",
            grant,
        )
    cursor = await superuser_conn.execute(
        "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s", (orphan_group,)
    )
    assert await cursor.fetchone() is None

    await superuser_conn.execute(
        SQL("GRANT USAGE ON SCHEMA {} TO {}").format(schema_id, Identifier(users["app"].name))
    )
    await superuser_conn.execute(
        SQL("GRANT SELECT ON {}.{} TO {}").format(
            schema_id, table_id, Identifier(users["app"].name)
        )
    )

    async def read_rows(role: RoleInfo) -> list[str]:
        async with await connect_as(role) as conn:
            cursor = await conn.execute(
                SQL("SELECT team FROM {}.{} ORDER BY team").format(schema_id, table_id)
            )
            return [row[0] for row in await cursor.fetchall()]

    assert await read_rows(users["all"]) == ["a", "b", "c"]
    assert await read_rows(users["a"]) == ["a"]
    assert await read_rows(users["b"]) == ["b"]
    assert await read_rows(users["none"]) == []
    assert await read_rows(users["app"]) == ["a", "b", "c"]

    async with await connect_as(users["noinherit"]) as conn:
        cursor = await conn.execute(
            "SELECT pg_catalog.pg_has_role(session_user, 'gw_managed', 'USAGE'), "
            "pg_catalog.pg_has_role(session_user, 'gw_managed', 'SET'), "
            "gateway_acl.is_managed()"
        )
        assert await cursor.fetchone() == (False, True, True)
        await conn.execute("SET ROLE gw_managed")
        cursor = await conn.execute(
            SQL("SELECT team FROM {}.{} ORDER BY team").format(schema_id, table_id)
        )
        assert await cursor.fetchall() == []

    async with await connect_as(users["a"]) as conn:
        cursor = await conn.execute(
            "SELECT session_user, gateway_acl.is_managed(), "
            "gateway_acl.allow_all(%s, %s), gateway_acl.allowed_values(%s, %s)",
            (target_admin.schema, table_name, target_admin.schema, table_name),
        )
        before = await cursor.fetchone()
        assert before == (users["a"].name, True, False, ["a"])
        await conn.execute(SQL("SET ROLE {}").format(Identifier(groups["a"])))
        cursor = await conn.execute(
            "SELECT session_user, gateway_acl.is_managed(), "
            "gateway_acl.allow_all(%s, %s), gateway_acl.allowed_values(%s, %s)",
            (target_admin.schema, table_name, target_admin.schema, table_name),
        )
        assert await cursor.fetchone() == before
        cursor = await conn.execute(
            SQL("SELECT team FROM {}.{} ORDER BY team").format(schema_id, table_id)
        )
        assert [row[0] for row in await cursor.fetchall()] == ["a"]

    async with await connect_as(target_admin.login) as admin_conn:
        cursor = await admin_conn.execute("SELECT gateway_acl.is_managed()")
        assert await cursor.fetchone() == (False,)
        cursor = await admin_conn.execute(
            SQL("SELECT team FROM {}.{} ORDER BY team").format(schema_id, table_id)
        )
        assert [row[0] for row in await cursor.fetchall()] == ["a", "b", "c"]

    hijack_schema = unique_name("hijack")
    fake_group = unique_name("gfake")
    await superuser_conn.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(fake_group)))
    await superuser_conn.execute(
        SQL("GRANT {} TO {}").format(Identifier(fake_group), Identifier(users["none"].name))
    )
    await superuser_conn.execute(SQL("CREATE SCHEMA {}").format(Identifier(hijack_schema)))
    await superuser_conn.execute(
        SQL("GRANT USAGE ON SCHEMA {} TO PUBLIC").format(Identifier(hijack_schema))
    )
    await superuser_conn.execute(
        SQL(
            "CREATE FUNCTION {}.is_managed() RETURNS boolean LANGUAGE sql AS $$ SELECT TRUE $$"
        ).format(Identifier(hijack_schema))
    )
    await superuser_conn.execute(
        SQL(
            "CREATE FUNCTION {}.allow_all(name, name) RETURNS boolean "
            "LANGUAGE sql AS $$ SELECT TRUE $$"
        ).format(Identifier(hijack_schema))
    )
    await superuser_conn.execute(
        SQL(
            "CREATE FUNCTION {}.allowed_values(name, name) RETURNS text[] "
            "LANGUAGE sql AS $$ SELECT ARRAY['a', 'b', 'c']::text[] $$"
        ).format(Identifier(hijack_schema))
    )

    async with await connect_as(users["none"]) as conn:
        await conn.execute(
            "CREATE TEMP TABLE row_grants "
            "(group_role name, schema_name name, table_name name, column_name name, value text)"
        )
        await conn.execute(
            "INSERT INTO pg_temp.row_grants VALUES (%s, %s, %s, '*', '*')",
            (fake_group, target_admin.schema, table_name),
        )
        await conn.execute(
            SQL("SET search_path TO {}, pg_temp, public").format(Identifier(hijack_schema))
        )
        cursor = await conn.execute(
            "SELECT is_managed(), allow_all(%s, %s), allowed_values(%s, %s)",
            (target_admin.schema, table_name, target_admin.schema, table_name),
        )
        assert await cursor.fetchone() == (True, True, ["a", "b", "c"])
        cursor = await conn.execute(
            "SELECT gateway_acl.is_managed(), "
            "gateway_acl.allow_all(%s, %s), gateway_acl.allowed_values(%s, %s)",
            (target_admin.schema, table_name, target_admin.schema, table_name),
        )
        assert await cursor.fetchone() == (True, False, [])
        cursor = await conn.execute(
            SQL("SELECT team FROM {}.{} ORDER BY team").format(schema_id, table_id)
        )
        assert await cursor.fetchall() == []
