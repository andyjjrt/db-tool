"""Plan §5 bullets 2-5: row-level control, multi-group union, grant-before-declare, write checks."""

import pytest

from db_gateway.permissions.rules import RuleConflict
from db_gateway.permissions.store import Tuple
from tests.acceptance.conftest import ALL_TEAMS, CONNECTION, Stack


async def test_s5_row_set_reader_sees_only_its_value(stack: Stack) -> None:
    """§5 列級: team='a' group sees only a."""
    user = await stack.new_user()
    group = await stack.new_group("rows", user)
    await stack.declare()
    await stack.row_set(group, "a")
    await stack.sync()
    assert await stack.teams(user) == ["a", "a"]


async def test_s5_table_reader_and_schema_reader_see_all_rows(stack: Stack) -> None:
    """§5 列級: table reader and schema reader see every row of a controlled table."""
    table_user, schema_user = await stack.new_user(), await stack.new_user()
    table_group = await stack.new_group("tr", table_user)
    schema_group = await stack.new_group("sr", schema_user)
    await stack.declare()
    await stack.rules.grant_table_reader(
        stack.actor, table_group, CONNECTION, stack.schema, "items"
    )
    await stack.rules.grant_schema_reader(stack.actor, schema_group, CONNECTION, stack.schema)
    await stack.sync()
    assert await stack.teams(table_user) == ALL_TEAMS
    assert await stack.teams(schema_user) == ALL_TEAMS


async def test_s5_no_rule_sees_zero_rows(stack: Stack) -> None:
    """§5 列級: a managed user with no rule reads 0 rows (not permission denied)."""
    user = await stack.new_user()
    await stack.new_group("empty", user)
    await stack.declare()
    await stack.sync()
    assert await stack.teams(user) == []


async def test_s5_multi_group_union_then_table_reader_group_sees_all(stack: Stack) -> None:
    """§5 多群組: in groups a and b -> a ∪ b; add a table-reader group -> all rows."""
    user = await stack.new_user()
    group_a = await stack.new_group("ga", user)
    group_b = await stack.new_group("gb", user)
    group_all = await stack.new_group("gall")
    await stack.declare()
    await stack.row_set(group_a, "a")
    await stack.row_set(group_b, "b")
    await stack.sync()
    assert await stack.teams(user) == ["a", "a", "b"]
    await stack.rules.grant_table_reader(stack.actor, group_all, CONNECTION, stack.schema, "items")
    await stack.rules.add_member(stack.actor, group_all, user.id)
    await stack.sync()
    assert await stack.teams(user) == ALL_TEAMS


async def test_s5_grant_before_declare_readers_see_all_rows_throughout(stack: Stack) -> None:
    """§5 先授權再宣告: existing readers see all rows before, during and after declaring."""
    user = await stack.new_user()
    group = await stack.new_group("early", user)
    await stack.rules.grant_table_reader(stack.actor, group, CONNECTION, stack.schema, "items")
    await stack.sync()
    seen: dict[str, list[str]] = {"before": await stack.teams(user)}

    async def during(writes: object, deletes: object) -> None:
        # RLS is already enabled on the table; the row_column tuple is not written yet.
        enabled = await stack.admin_sql(
            "SELECT relrowsecurity FROM pg_catalog.pg_class WHERE oid = %s::regclass",
            f'"{stack.schema}".items',
        )
        assert enabled == [(True,)]
        seen["during"] = await stack.teams(user)

    stack.store.before_write = during
    await stack.declare()
    stack.store.before_write = None
    seen["after"] = await stack.teams(user)
    await stack.sync()
    seen["synced"] = await stack.teams(user)
    assert seen == {key: ALL_TEAMS for key in ("before", "during", "after", "synced")}


async def test_s5_write_check_schema_and_table_rules_overlap(stack: Stack) -> None:
    """§5 寫入時檢查: schema rule + table rule for one group and schema -> RuleConflict."""
    group = await stack.new_group("overlap")
    await stack.rules.grant_schema_reader(stack.actor, group, CONNECTION, stack.schema)
    with pytest.raises(RuleConflict):
        await stack.rules.grant_table_reader(stack.actor, group, CONNECTION, stack.schema, "items")
    other = await stack.new_group("overlap2")
    await stack.rules.grant_table_reader(stack.actor, other, CONNECTION, stack.schema, "items")
    with pytest.raises(RuleConflict):
        await stack.rules.grant_schema_reader(stack.actor, other, CONNECTION, stack.schema)


async def test_s5_write_check_row_set_on_uncontrolled_table(stack: Stack) -> None:
    """§5 寫入時檢查: row_set on an uncontrolled table -> RuleConflict, nothing written."""
    group = await stack.new_group("uncontrolled")
    with pytest.raises(RuleConflict):
        await stack.row_set(group, "a")
    assert (
        await stack.store.read(object="row_set:", user=f"db_table:target/{stack.schema}/items")
        == []
    )


async def test_s5_write_check_undeclare_while_row_sets_remain(stack: Stack) -> None:
    """§5 寫入時檢查: undeclare while row_sets remain -> RuleConflict; works once they are gone."""
    user = await stack.new_user()
    group = await stack.new_group("remain", user)
    await stack.declare()
    await stack.row_set(group, "a")
    with pytest.raises(RuleConflict):
        await stack.rules.undeclare_row_policy(stack.actor, CONNECTION, stack.schema, "items")
    declared = await stack.store.read(
        object=f"db_table:target/{stack.schema}/items", relation="row_column"
    )
    assert declared == [Tuple("column:team", "row_column", f"db_table:target/{stack.schema}/items")]
    await stack.sync()
    assert await stack.teams(user) == ["a", "a"]
    assert (
        await stack.rules.revoke_row_set(
            stack.actor, group, CONNECTION, stack.schema, "items", "team", "a"
        )
        == "synced"
    )
    assert (
        await stack.rules.undeclare_row_policy(stack.actor, CONNECTION, stack.schema, "items")
        is None
    )
