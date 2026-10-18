"""Plan §5 繞過: attempts to see hidden rows, and roles that must keep working."""

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from tests.acceptance.conftest import ALL_TEAMS, Stack


async def _controlled_world(stack: Stack):  # type: ignore[no-untyped-def]
    """A controlled table where `a_user` (group a) sees only team a."""
    a_user = await stack.new_user()
    group = await stack.new_group("byp", a_user)
    await stack.declare()
    await stack.row_set(group, "a")
    await stack.sync()
    assert await stack.teams(a_user) == ["a", "a"]
    return a_user, group


async def _two_group_member(stack: Stack):  # type: ignore[no-untyped-def]
    """A user in group a (team a) and group b (team b) on a controlled table."""
    user = await stack.new_user()
    group_a = await stack.new_group("seta", user)
    group_b = await stack.new_group("setb", user)
    await stack.declare()
    await stack.row_set(group_a, "a")
    await stack.row_set(group_b, "b")
    await stack.sync()
    assert await stack.teams(user) == ["a", "a", "b"]
    return user, group_a


async def test_s5_bypass_set_role_to_group_role_keeps_row_count(stack: Stack) -> None:
    """§5 繞過: `SET ROLE g_<group>` -> identical rows (session_user does not change).

    Test scaffolding: the selected group is given schema USAGE and table SELECT so the
    read reaches RLS under the group role instead of stopping at the ACL check. A user
    in both an a and a b group shows visibility is session-wide, not the group's alone.
    """
    user, group_a = await _two_group_member(stack)
    role = Identifier(f"g_{group_a}")
    await stack.superuser.execute(
        SQL("GRANT USAGE ON SCHEMA {} TO {}").format(Identifier(stack.schema), role)
    )
    await stack.superuser.execute(SQL("GRANT SELECT ON {} TO {}").format(stack.rel(), role))
    query = SQL("SELECT team FROM {} ORDER BY id").format(stack.rel())
    async with await stack.connect_as(user.login) as conn:
        before = [r[0] for r in await (await conn.execute(query)).fetchall()]
        await conn.execute(SQL("SET ROLE {}").format(role))
        cursor = await conn.execute("SELECT current_user, session_user")
        assert await cursor.fetchone() == (f"g_{group_a}", user.login.name)
        after = [r[0] for r in await (await conn.execute(query)).fetchall()]
    assert before == ["a", "a", "b"]
    assert after == before


async def test_s5_bypass_set_role_default_group_role_is_denied(stack: Stack) -> None:
    """Documents the default: a gateway-created group role has no schema USAGE, so reads fail."""
    user, group_a = await _two_group_member(stack)
    async with await stack.connect_as(user.login) as conn:
        await conn.execute(SQL("SET ROLE {}").format(Identifier(f"g_{group_a}")))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await conn.execute(SQL("SELECT team FROM {}").format(stack.rel()))


async def test_s5_bypass_allowed_values_returns_only_own_values(stack: Stack) -> None:
    """§5 繞過: calling `gateway_acl.allowed_values` directly -> only the caller's values."""
    a_user, _ = await _controlled_world(stack)
    b_user = await stack.new_user()
    b_group = await stack.new_group("byp_b", b_user)
    await stack.row_set(b_group, "b")
    await stack.sync()
    for person, expected in ((a_user, ["a"]), (b_user, ["b"])):
        async with await stack.connect_as(person.login) as conn:
            cursor = await conn.execute(
                "SELECT gateway_acl.allowed_values(%s, 'items')", (stack.schema,)
            )
            assert await cursor.fetchone() == (expected,)
            cursor = await conn.execute(
                "SELECT gateway_acl.allow_all(%s, 'items')", (stack.schema,)
            )
            assert await cursor.fetchone() == (False,)


async def test_s5_bypass_row_grants_is_permission_denied(stack: Stack) -> None:
    """§5 繞過: `SELECT FROM gateway_acl.row_grants` -> permission denied."""
    user, _ = await _controlled_world(stack)
    async with await stack.connect_as(user.login) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await conn.execute("SELECT * FROM gateway_acl.row_grants")


async def test_s5_bypass_same_name_function_and_search_path_hijack_fail(stack: Stack) -> None:
    """§5 繞過: same-name functions, temp `row_grants` and a hijacked search_path fail."""
    user = await stack.new_user()
    group = await stack.new_group("hijack", user)
    await stack.declare()
    await stack.row_set(group, "b")
    await stack.sync()
    hijack = stack.unique_name("hijack")
    su = stack.superuser
    await su.execute(SQL("CREATE SCHEMA {}").format(Identifier(hijack)))
    await su.execute(SQL("GRANT USAGE ON SCHEMA {} TO PUBLIC").format(Identifier(hijack)))
    for name, ret, body in (
        ("is_managed()", "boolean", "SELECT TRUE"),
        ("allow_all(name, name)", "boolean", "SELECT TRUE"),
        ("allowed_values(name, name)", "text[]", "SELECT ARRAY['a','b','c']::text[]"),
    ):
        await su.execute(
            SQL("CREATE FUNCTION {}.{} RETURNS {} LANGUAGE sql AS {}").format(
                Identifier(hijack),
                SQL(name),  # type: ignore[arg-type]
                SQL(ret),  # type: ignore[arg-type]
                SQL("$$" + body + "$$"),  # type: ignore[arg-type]
            )
        )
    async with await stack.connect_as(user.login) as conn:
        await conn.execute(
            "CREATE TEMP TABLE row_grants (group_role name, schema_name name, table_name name, "
            "column_name name, value text)"
        )
        await conn.execute(
            "INSERT INTO pg_temp.row_grants VALUES (%s, %s, 'items', '*', '*')",
            (f"g_{group}", stack.schema),
        )
        await conn.execute(SQL("SET search_path TO {}, pg_temp, public").format(Identifier(hijack)))
        cursor = await conn.execute(SQL("SELECT team FROM {} ORDER BY id").format(stack.rel()))
        assert [r[0] for r in await cursor.fetchall()] == ["b"]
        cursor = await conn.execute(
            "SELECT gateway_acl.allow_all(%s, 'items'), gateway_acl.allowed_values(%s, 'items')",
            (stack.schema, stack.schema),
        )
        assert await cursor.fetchone() == (False, ["b"])


async def test_s5_bypass_owner_bypassrls_and_non_gateway_role_read_all_rows(
    stack: Stack, role_factory
) -> None:  # type: ignore[no-untyped-def]
    """§5 繞過: owner, a BYPASSRLS role and a non-gateway role read everything (gw_passthrough)."""
    await _controlled_world(stack)
    from tests.conftest import RoleInfo  # noqa: F401

    bypass = await role_factory("bypass")
    plain = await role_factory("app")
    su = stack.superuser
    await su.execute(SQL("ALTER ROLE {} BYPASSRLS").format(Identifier(bypass.name)))
    for role in (bypass, plain):
        await su.execute(
            SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                Identifier(stack.schema), Identifier(role.name)
            )
        )
        await su.execute(SQL("GRANT SELECT ON {} TO {}").format(stack.rel(), Identifier(role.name)))
    for login in (stack.admin.login, bypass, plain):
        async with await stack.connect_as(login) as conn:
            cursor = await conn.execute(SQL("SELECT team FROM {} ORDER BY id").format(stack.rel()))
            assert [r[0] for r in await cursor.fetchall()] == ALL_TEAMS, login.name
