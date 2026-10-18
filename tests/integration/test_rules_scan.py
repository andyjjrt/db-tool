"""Production scanner wiring, with a real bypass-owner view and target admin."""

import psycopg
import pytest
from psycopg.sql import SQL, Identifier, Literal

from db_gateway.permissions import ids
from db_gateway.permissions.rules import RuleConflict
from db_gateway.permissions.store import Tuple
from tests.integration.test_api_admin import ApiWorld
from tests.integration.test_api_admin import api_world as api_world
from tests.integration.test_target_db import target_admin as target_admin


async def test_superuser_view_blocks_grants_and_declaration_before_changes(
    api_world: ApiWorld, superuser_conn: psycopg.AsyncConnection
) -> None:
    w = api_world
    schema = w.admin.schema
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    await superuser_conn.execute(
        SQL("CREATE VIEW {} AS SELECT * FROM {}").format(
            Identifier(schema, "leak"), Identifier(schema, "items")
        )
    )
    await superuser_conn.execute(
        SQL("GRANT SELECT ON {} TO {} WITH GRANT OPTION").format(
            Identifier(schema, "leak"), Identifier(w.admin.login.name)
        )
    )
    # With no declarations the view is not yet unsafe, and can be granted.
    view = {**w.table, "table": "leak"}
    await w.request("POST", "/grants/table-reader", view, 201)
    await w.request("POST", "/sync")
    rules = w.app.state.rules
    with pytest.raises(RuleConflict, match=r"leak.*bypass_owner"):
        await rules.declare_row_policy(w.actor, "target", schema, "items", "team")
    assert await w.app.state.store.read(ids.db_table("target", schema, "items"), "row_column") == []
    cursor = await superuser_conn.execute(
        SQL(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = {}::regclass"
        ).format(Literal(Identifier(schema, "items").as_string(superuser_conn)))
    )
    assert await cursor.fetchone() == (False, False)
    await w.request("DELETE", "/grants/table-reader", view)
    await rules.declare_row_policy(w.actor, "target", schema, "items", "team")
    with pytest.raises(RuleConflict, match=r"leak.*bypass_owner"):
        await rules.grant_table_reader(w.actor, "analysts", "target", schema, "leak")
    with pytest.raises(RuleConflict, match=r"leak.*bypass_owner"):
        await rules.grant_schema_reader(w.actor, "analysts", "target", schema)
    await superuser_conn.execute(
        SQL("ALTER VIEW {} SET (security_invoker = true)").format(Identifier(schema, "leak"))
    )
    await rules.grant_table_reader(w.actor, "analysts", "target", schema, "leak")


async def test_reconciler_reports_unsafe_view_and_definer_without_altering_them(
    api_world: ApiWorld, superuser_conn: psycopg.AsyncConnection
) -> None:
    w = api_world
    schema = w.admin.schema
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    await w.request("POST", "/row-policies", w.policy, 201)
    await superuser_conn.execute(
        SQL("CREATE VIEW {} AS SELECT * FROM {}").format(
            Identifier(schema, "leak"), Identifier(schema, "items")
        )
    )
    await superuser_conn.execute(
        SQL("GRANT SELECT ON {} TO {} WITH GRANT OPTION").format(
            Identifier(schema, "leak"), Identifier(w.admin.login.name)
        )
    )
    await superuser_conn.execute(
        SQL(
            "CREATE FUNCTION {}() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'"
        ).format(Identifier(schema, "definer"))
    )
    # Simulate a pre-existing rule, bypassing the new refusal boundary deliberately.
    await w.app.state.store.write(
        [Tuple(ids.group_member("analysts"), "reader", ids.db_table("target", schema, "leak"))]
    )
    await w.request("POST", "/sync")
    snapshot_sql = SQL(
        "SELECT c.relowner, c.reloptions, c.relacl::text, p.proowner, p.proacl::text "
        "FROM pg_class c, pg_proc p WHERE c.oid = {}::regclass AND p.oid = {}::regprocedure"
    ).format(
        Literal(Identifier(schema, "leak").as_string(superuser_conn)),
        Literal(Identifier(schema, "definer").as_string(superuser_conn) + "()"),
    )
    cursor = await superuser_conn.execute(snapshot_sql)
    before = await cursor.fetchone()
    for dry_run in (True, False):
        report = await w.app.state.reconciler.reconcile("target", dry_run=dry_run)
        assert report.error is None
        assert {"unsafe_view", "definer_function"} <= {d.kind for d in report.reported}
        assert report.fixes == []
    cursor = await superuser_conn.execute(snapshot_sql)
    assert await cursor.fetchone() == before
