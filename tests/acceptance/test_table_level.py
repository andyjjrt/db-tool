"""Plan §5 bullet 1: table-level grant and revoke, each with a 5 s deadline.

Every deadline starts before the service call and covers the sync/apply plus the real
login query that observes the result, so a late observation fails the test.
"""

import asyncio
import time
from collections.abc import Sequence

from db_gateway.permissions.executor import PgExecutor
from db_gateway.permissions.types import GrantTableSelect, PgOp
from tests.acceptance.conftest import ALL_TEAMS, Stack

DEADLINE_S = 5.0


def _signal_when_applied(stack: Stack, monkeypatch, kind: type[PgOp]) -> asyncio.Event:  # type: ignore[no-untyped-def]
    """Set the returned event once the real executor finishes applying an op of ``kind``."""
    applied = asyncio.Event()
    real_apply = PgExecutor.apply

    async def apply(connection: str, ops: Sequence[PgOp]) -> list[PgOp]:
        skipped = await real_apply(stack.executor, connection, ops)
        if any(isinstance(op, kind) for op in ops):
            applied.set()
        return list(skipped)

    monkeypatch.setattr(stack.executor, "apply", apply)
    return applied


async def test_s5_table_grant_visible_within_5s_then_revoke_denied_on_uncontrolled(
    stack: Stack, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """§5 表級: grant -> SELECT works within 5 s; revoke -> `permission denied` (uncontrolled)."""
    user = await stack.new_user()
    group = await stack.new_group("tbl", user)
    assert await stack.denied(user, "plain")
    applied = _signal_when_applied(stack, monkeypatch, GrantTableSelect)
    runner = asyncio.create_task(stack.syncer.run())
    try:
        start = time.monotonic()
        async with asyncio.timeout(DEADLINE_S):
            await stack.rules.grant_table_reader(
                stack.actor, group, "target", stack.schema, "plain"
            )
            await applied.wait()
            assert await stack.teams(user, "plain") == ALL_TEAMS
        assert time.monotonic() - start <= DEADLINE_S
    finally:
        await stack.syncer.stop()
        await runner

    start = time.monotonic()
    async with asyncio.timeout(DEADLINE_S):
        result = await stack.rules.revoke_table_reader(
            stack.actor, group, "target", stack.schema, "plain"
        )
        assert await stack.denied(user, "plain")
    assert time.monotonic() - start <= DEADLINE_S
    assert result == "synced"


async def test_s5_table_revoke_gives_zero_rows_on_controlled_table(stack: Stack) -> None:
    """§5 表級: revoke on a row-controlled table -> 0 rows within 5 s (not permission denied)."""
    user = await stack.new_user()
    group = await stack.new_group("tbl", user)
    await stack.declare()
    await stack.rules.grant_table_reader(stack.actor, group, "target", stack.schema, "items")
    await stack.sync()
    assert await stack.teams(user) == ALL_TEAMS
    start = time.monotonic()
    async with asyncio.timeout(DEADLINE_S):
        result = await stack.rules.revoke_table_reader(
            stack.actor, group, "target", stack.schema, "items"
        )
        rows = await stack.teams(user)
    assert time.monotonic() - start <= DEADLINE_S
    assert result == "synced"
    assert rows == []


async def test_s5_schema_grant_and_revoke_inline(stack: Stack) -> None:
    """§5 表級 (schema variant): schema reader sees every table; revoke denies within 5 s."""
    user = await stack.new_user()
    group = await stack.new_group("sch", user)
    await stack.rules.grant_schema_reader(stack.actor, group, "target", stack.schema)
    await stack.sync()
    assert await stack.teams(user, "plain") == ALL_TEAMS
    start = time.monotonic()
    async with asyncio.timeout(DEADLINE_S):
        result = await stack.rules.revoke_schema_reader(stack.actor, group, "target", stack.schema)
        assert await stack.denied(user, "plain")
    assert time.monotonic() - start <= DEADLINE_S
    assert result == "synced"
