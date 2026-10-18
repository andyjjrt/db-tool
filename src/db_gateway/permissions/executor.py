"""Apply permission changes atomically as a target connection's admin account."""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

import psycopg
from psycopg.errors import Diagnostic
from psycopg.pq import TransactionStatus
from psycopg.sql import SQL, Composable, Composed, Identifier, Literal

from db_gateway.permissions.pg_ops import render, required_objects
from db_gateway.permissions.types import CreateGroupRole, DropGroupRole, PgOp, RevokeMembership

logger = logging.getLogger(__name__)


class ApplyError(Exception):
    """A failed change; ``op`` is None if connection acquisition or setup failed."""

    def __init__(self, connection: str, op: PgOp | None, original: Exception) -> None:
        self.connection = connection
        self.op = op
        self.original = original
        super().__init__(f"apply on {connection!r}, op={op!r}: {original}")


class TransientApplyError(ApplyError):
    """A role still has dependencies, possibly in another database; retry later."""


@dataclass(frozen=True, slots=True)
class SkippedOp:
    op: PgOp
    reason: str


class PgExecutor:
    """Serialize each connection's changes and run each call in one transaction.

    ``connect(name)`` must return a fresh, idle psycopg async connection logged
    in as that target's admin. The executor owns and closes it, including on
    failure. No role switching or privilege repair is performed.

    ``apply`` returns the skipped ops; ``last_skipped[name]`` also gives the
    reasons for the most recent attempt (even if that attempt rolled back).
    Locks cover acquisition, commit/rollback, notice cleanup, and closing.
    """

    def __init__(self, connect: Callable[[str], Awaitable[psycopg.AsyncConnection]]) -> None:
        self._connect = connect
        self._locks: dict[str, asyncio.Lock] = {}
        self.last_skipped: dict[str, tuple[SkippedOp, ...]] = {}

    async def apply(self, connection: str, ops: Sequence[PgOp]) -> tuple[PgOp, ...]:
        lock = self._locks.setdefault(connection, asyncio.Lock())
        async with lock:
            skipped: list[SkippedOp] = []
            current: PgOp | None = None
            warnings: list[psycopg.Error] = []

            def notice(diag: Diagnostic) -> None:
                # Diagnostics are only valid during the callback. Preserve the
                # SQLSTATE and message, not the borrowed libpq diagnostic.
                if diag.sqlstate in {"01007", "01006"}:
                    error = psycopg.Error(diag.message_primary or "")
                    error.sqlstate = diag.sqlstate
                    warnings.append(error)

            try:
                async with await self._connect(connection) as conn:
                    if conn.info.transaction_status is not TransactionStatus.IDLE:
                        raise ValueError("PgExecutor requires a fresh idle connection")
                    conn.add_notice_handler(notice)
                    try:
                        async with conn.transaction():
                            await conn.execute(SQL("SET LOCAL client_min_messages = 'warning'"))
                            if any(isinstance(op, CreateGroupRole) for op in ops):
                                await conn.execute(SQL("SET LOCAL createrole_self_grant = ''"))
                            for current in ops:
                                reason = await _missing_reason(conn, current)
                                statements: list[Composable] | None = None
                                if reason is None and isinstance(current, RevokeMembership):
                                    statements = await _membership_revokes(conn, current)
                                    if not statements:
                                        reason = "membership does not exist"
                                if reason is not None:
                                    skipped.append(SkippedOp(current, reason))
                                    logger.info(
                                        "Skipping op %r on connection %s: %s",
                                        current,
                                        connection,
                                        reason,
                                    )
                                    continue
                                if statements is None:
                                    statements = render(current)
                                for statement in statements:
                                    warnings.clear()
                                    await conn.execute(Composed([statement]))
                                    if warnings:
                                        raise warnings[0]
                    finally:
                        conn.remove_notice_handler(notice)
                return tuple(item.op for item in skipped)
            except Exception as exc:
                error = (
                    TransientApplyError
                    if isinstance(current, DropGroupRole)
                    and isinstance(exc, psycopg.Error)
                    and exc.sqlstate == "2BP01"
                    else ApplyError
                )
                raise error(connection, current, exc) from exc
            finally:
                self.last_skipped[connection] = tuple(skipped)


async def _missing_reason(conn: psycopg.AsyncConnection, op: PgOp) -> str | None:
    required = required_objects(op)
    for role in required.roles:
        cursor = await conn.execute(
            SQL("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {}").format(Literal(role))
        )
        if await cursor.fetchone() is None:
            return f"role {role!r} does not exist"
    for schema in required.schemas:
        cursor = await conn.execute(
            SQL("SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = {}").format(Literal(schema))
        )
        if await cursor.fetchone() is None:
            return f"schema {schema!r} does not exist"
    for schema, table in required.tables:
        cursor = await conn.execute(
            SQL(
                "SELECT 1 FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = {} AND c.relname = {}"
            ).format(Literal(schema), Literal(table))
        )
        if await cursor.fetchone() is None:
            return f"table {schema!r}.{table!r} does not exist"
    return None


async def _membership_revokes(
    conn: psycopg.AsyncConnection, op: RevokeMembership
) -> list[Composable]:
    cursor = await conn.execute(
        SQL(
            "SELECT grantor.rolname, grantor.rolname = CURRENT_USER "
            "FROM pg_catalog.pg_auth_members m "
            "JOIN pg_catalog.pg_roles g ON g.oid = m.roleid "
            "JOIN pg_catalog.pg_roles u ON u.oid = m.member "
            "JOIN pg_catalog.pg_roles grantor ON grantor.oid = m.grantor "
            "WHERE g.rolname = {} AND u.rolname = {} ORDER BY grantor.rolname"
        ).format(Literal(op.group), Literal(op.member))
    )
    statements: list[Composable] = []
    for grantor, is_admin in await cursor.fetchall():
        statement = SQL("REVOKE {} FROM {}").format(Identifier(op.group), Identifier(op.member))
        if not is_admin:
            statement += SQL(" GRANTED BY {}").format(Identifier(grantor))
        statements.append(statement)
    return statements
