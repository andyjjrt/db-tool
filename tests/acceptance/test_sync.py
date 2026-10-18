"""Plan §5 同步: OpenFGA outage, catch-up after recovery, and drift from a manual GRANT."""

import pytest
from psycopg.sql import SQL, Identifier

from db_gateway.permissions.store import PermissionStoreUnavailable
from db_gateway.permissions.types import RevokeTableSelect
from tests.acceptance.conftest import ALL_TEAMS, CONNECTION, Stack


async def test_s5_openfga_outage_keeps_queries_working_and_syncer_catches_up(
    stack: Stack,
) -> None:
    """§5 同步: OpenFGA down -> existing queries work; after recovery the Syncer catches up."""
    user = await stack.new_user()
    group = await stack.new_group("outage", user)
    await stack.rules.grant_table_reader(stack.actor, group, CONNECTION, stack.schema, "items")
    await stack.sync()
    token = (await stack.syncer.status())[0]["continuation_token"]
    assert await stack.teams(user) == ALL_TEAMS

    # A grant lands in OpenFGA, then the change stream becomes unreachable.
    await stack.rules.grant_table_reader(stack.actor, group, CONNECTION, stack.schema, "plain")
    stack.store.changes_down = True
    await stack.syncer.sync_once(CONNECTION)
    status = (await stack.syncer.status())[0]
    assert "OpenFGA unavailable" in (status["last_error"] or "")
    assert status["continuation_token"] == token
    assert await stack.teams(user) == ALL_TEAMS  # existing access is untouched
    assert await stack.denied(user, "plain")  # the pending grant is not applied yet

    # The admin API sees the outage as PermissionStoreUnavailable (503) and PG is not touched.
    stack.store.all_down = True
    with pytest.raises(PermissionStoreUnavailable):
        await stack.rules.revoke_table_reader(stack.actor, group, CONNECTION, stack.schema, "items")
    assert await stack.teams(user) == ALL_TEAMS

    stack.store.all_down = False
    stack.store.changes_down = False
    await stack.sync()
    assert (await stack.syncer.status())[0]["continuation_token"] != token
    assert await stack.teams(user, "plain") == ALL_TEAMS
    assert await stack.teams(user) == ALL_TEAMS


async def test_s5_manual_grant_is_reported_as_drift_and_reconcile_removes_it(
    stack: Stack,
) -> None:
    """§5 同步: a DBA's manual GRANT -> drift reported (dry run) -> reconcile removes it."""
    user = await stack.new_user()
    group = await stack.new_group("drift", user)
    await stack.rules.grant_table_reader(stack.actor, group, CONNECTION, stack.schema, "items")
    await stack.sync()
    assert await stack.denied(user, "plain")

    await stack.admin_sql(
        SQL("GRANT SELECT ON {} TO {}").format(stack.rel("plain"), Identifier(f"g_{group}"))
    )
    assert await stack.teams(user, "plain") == ALL_TEAMS  # the drift is real

    dry = await stack.reconciler.reconcile(CONNECTION, dry_run=True)
    assert dry.fixes == [RevokeTableSelect(stack.schema, "plain", f"g_{group}")]
    assert await stack.teams(user, "plain") == ALL_TEAMS  # dry run changes nothing

    report = await stack.reconciler.reconcile_strict(CONNECTION)
    assert report.fixes == dry.fixes
    assert await stack.denied(user, "plain")
    assert await stack.teams(user) == ALL_TEAMS  # the legitimate grant survives
    assert (await stack.reconciler.reconcile(CONNECTION, dry_run=True)).fixes == []
