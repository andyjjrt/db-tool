"""Plan §5 繞過 / §11: unsafe views and SECURITY DEFINER functions; exposing grants are refused."""

import pytest
from psycopg.sql import SQL, Identifier

from db_gateway.permissions import scan
from db_gateway.permissions.rules import RuleConflict
from tests.acceptance.conftest import ALL_TEAMS, CONNECTION, Stack, needs_scanner
from tests.conftest import PG_USER


async def _create_view(stack: Stack, name: str = "leaky", base: str = "items") -> None:
    async with await stack.connect(CONNECTION) as conn:
        await conn.execute(
            SQL("CREATE VIEW {} AS SELECT * FROM {}").format(stack.rel(name), stack.rel(base))
        )


async def _chown_to_superuser(stack: Stack, name: str = "leaky") -> None:
    await stack.superuser.execute(
        SQL("ALTER TABLE {} OWNER TO {}").format(stack.rel(name), Identifier(PG_USER))
    )


async def _superuser_view(stack: Stack, name: str = "leaky", base: str = "items") -> None:
    await _create_view(stack, name, base)
    await _chown_to_superuser(stack, name)


async def test_s5_superuser_owned_view_over_controlled_table_is_found_and_really_leaks(
    stack: Stack,
) -> None:
    """§5 繞過 / §11: a superuser-owned view over a controlled table is found by the scan."""
    user = await stack.new_user()
    await stack.new_group("nobody", user)
    await stack.declare()
    await _superuser_view(stack)
    async with await stack.connect(CONNECTION) as conn:
        found = await scan.unsafe_views(conn, [(stack.schema, "items")])
    assert found == [
        scan.UnsafeView(
            stack.schema, "leaky", "view", PG_USER, ((stack.schema, "items"),), "bypass_owner"
        )
    ]
    # Why the scan matters: a direct grant on the view hands out every row.
    await stack.superuser.execute(
        SQL("GRANT SELECT ON {} TO {}").format(stack.rel("leaky"), Identifier(user.login.name))
    )
    assert await stack.teams(user, "leaky") == ALL_TEAMS
    assert await stack.teams(user) == []


async def test_s5_security_definer_function_is_found(stack: Stack) -> None:
    """§5 繞過 / §11: a SECURITY DEFINER function is reported with its owner's RLS bypass."""
    async with await stack.connect(CONNECTION) as conn:
        await conn.execute(
            SQL(
                "CREATE FUNCTION {}.peek() RETURNS bigint LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog AS $$ SELECT count(*) FROM {} $$"
            ).format(Identifier(stack.schema), stack.rel())
        )
        found = await scan.definer_functions(conn)
    assert [(f.schema, f.name, f.owner, f.owner_bypasses_rls) for f in found] == [
        (stack.schema, "peek", stack.admin.login.name, False)
    ]


@needs_scanner
async def test_s5_grant_table_reader_on_unsafe_view_is_refused(stack: Stack) -> None:
    """§11: grant_table_reader on an unsafe view is refused; the member still reads nothing."""
    member = await stack.new_user()
    group = await stack.new_group("viewer", member)
    await stack.declare()
    await _superuser_view(stack)
    assert await stack.denied(member, "leaky")
    with pytest.raises(RuleConflict):
        await stack.rules.grant_table_reader(stack.actor, group, CONNECTION, stack.schema, "leaky")
    assert await stack.denied(member, "leaky")
    await stack.sync()
    assert await stack.denied(member, "leaky")
    assert await stack.store.read(object=f"db_table:target/{stack.schema}/leaky") == []
    # A safe object is still grantable.
    await stack.rules.grant_table_reader(stack.actor, group, CONNECTION, stack.schema, "plain")
    await stack.sync()
    assert await stack.teams(member, "plain") == ALL_TEAMS
    assert await stack.denied(member, "leaky")


@needs_scanner
async def test_s5_grant_schema_reader_covering_unsafe_view_is_refused(stack: Stack) -> None:
    """§11: grant_schema_reader over an unsafe view is refused; the member still reads nothing."""
    member = await stack.new_user()
    group = await stack.new_group("viewer", member)
    await stack.declare()
    await _superuser_view(stack)
    assert await stack.denied(member, "leaky")
    with pytest.raises(RuleConflict):
        await stack.rules.grant_schema_reader(stack.actor, group, CONNECTION, stack.schema)
    assert await stack.denied(member, "leaky")
    assert await stack.denied(member, "plain")
    await stack.sync()
    assert await stack.denied(member, "leaky")
    assert await stack.denied(member, "plain")
    assert await stack.store.read(object=f"db_schema:target/{stack.schema}") == []


@needs_scanner
async def test_s5_declare_row_policy_while_a_group_reads_the_unsafe_view_is_refused(
    stack: Stack,
) -> None:
    """§11: declaring the base table is refused and leaves visibility and control unchanged."""
    member = await stack.new_user()
    outsider = await stack.new_user()
    group = await stack.new_group("viewer", member)
    await stack.new_group("others", outsider)
    # The admin account can only GRANT on the view while it still owns it; the hand-over
    # to a superuser afterwards keeps the grant (ALTER ... OWNER does not revoke it).
    await _create_view(stack)
    await stack.rules.grant_table_reader(stack.actor, group, CONNECTION, stack.schema, "leaky")
    await stack.rules.grant_table_reader(stack.actor, group, CONNECTION, stack.schema, "items")
    await stack.sync()
    await _chown_to_superuser(stack)

    async def observed() -> tuple[object, ...]:
        return (
            await stack.teams(member, "leaky"),
            await stack.teams(member, "items"),
            # An outsider has no grant: permission denied while the table is uncontrolled,
            # but 0 rows if RLS had been (even partly) enabled.
            await stack.denied(outsider, "items"),
            await stack.denied(outsider, "leaky"),
        )

    before = await observed()
    assert before == (ALL_TEAMS, ALL_TEAMS, True, True)
    with pytest.raises(RuleConflict):
        await stack.declare()
    assert await observed() == before
    await stack.sync()
    assert await observed() == before
    declared = await stack.store.read(
        object=f"db_table:target/{stack.schema}/items", relation="row_column"
    )
    assert declared == []
    assert await stack.admin_sql(
        "SELECT relrowsecurity FROM pg_catalog.pg_class WHERE oid = %s::regclass",
        f'"{stack.schema}".items',
    ) == [(False,)]
