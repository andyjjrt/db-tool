"""Admin-side writes to the permission model, with the write-time checks of plan §2.4.

``RuleService`` is the layer behind the admin API: groups, members, table / schema /
row rules, row-control declarations and admins. Every mutating method holds one lock
across "check -> write", so two admins writing at once cannot both pass a check that
only one of them may pass. The lock is per instance; the application builds exactly one
``RuleService`` per process, which makes it the global lock of §2.4.

Each mutating method writes exactly one ``audit_log`` row of kind ``admin`` when it
completes (including a PG step that failed after the SQLite/OpenFGA part was done); a
call rejected by a check writes nothing. The ``detail`` JSON carries the action, its
arguments, the tuples written and deleted and, on a PG failure, ``error``.

Errors: ``RuleConflict`` (409), ``NotFound`` (404), ``AdminForbidden`` (403) and
``ValueError`` for invalid input (400).
"""

import asyncio
import re
from collections.abc import Sequence, Set
from dataclasses import asdict
from typing import Any, Protocol

import aiosqlite

from db_gateway import metadata
from db_gateway.metadata import audit
from db_gateway.permissions import ids
from db_gateway.permissions.admin import (
    INITIAL_ADMINS,
    AdminChecker,
    AdminForbidden,
    AdminUser,
    admin_tuple,
    ensure_can_add_admin,
    ensure_can_remove_admin,
)
from db_gateway.permissions.executor_protocol import Executor
from db_gateway.permissions.mapping import row_policy_disable_ops, row_policy_enable_ops
from db_gateway.permissions.store import MAX_TUPLES_PER_WRITE, PermissionStore, Tuple
from db_gateway.permissions.types import ALL, CreateGroupRole, DropGroupRole, PgOp, group_role

__all__ = [
    "AdminForbidden",
    "NotFound",
    "PartitionStats",
    "RuleConflict",
    "RuleService",
]

_GROUP_NAME = re.compile(r"[a-z][a-z0-9_]{0,40}")


class RuleConflict(Exception):
    """The write conflicts with an existing rule or state; the API maps it to 409."""


class NotFound(Exception):
    """A named group, connection, user or declaration does not exist; the API maps it to 404."""


class PartitionStats(Protocol):
    async def distinct_count(
        self, connection: str, schema: str, table: str, column: str, limit: int
    ) -> int:
        """Number of distinct values of the column; may stop counting at limit + 1."""
        ...


def _no_wildcard(what: str, value: str) -> None:
    if value == ALL:
        raise ValueError(f"'*' is not a legal {what}")


def _tuples(items: Sequence[Tuple]) -> list[dict[str, str]]:
    return [asdict(item) for item in items]


class RuleService:
    def __init__(
        self,
        db: aiosqlite.Connection,
        store: PermissionStore,
        executor: Executor,
        partition_stats: PartitionStats,
        *,
        distinct_limit: int = 200,
        initial_admins: Set[str] = INITIAL_ADMINS,
    ) -> None:
        self._db = db
        self._store = store
        self._executor = executor
        self._stats = partition_stats
        self._distinct_limit = distinct_limit
        self._initial_admins = initial_admins
        self._lock = asyncio.Lock()

    # --- lookups -------------------------------------------------------------------

    async def _connections(self) -> dict[str, int]:
        async with self._db.execute("SELECT name, id FROM connections ORDER BY id") as cur:
            return {name: id_ for name, id_ in await cur.fetchall()}

    async def _connection_id(self, name: str) -> int:
        async with self._db.execute("SELECT id FROM connections WHERE name = ?", (name,)) as cur:
            row = await cur.fetchone()
        if row is None:
            raise NotFound(f"connection not found: {name}")
        return row[0]

    async def _require_group(self, name: str) -> None:
        async with self._db.execute("SELECT 1 FROM groups WHERE name = ?", (name,)) as cur:
            if await cur.fetchone() is None:
                raise NotFound(f"group not found: {name}")

    async def _user(self, user_id: int) -> AdminUser:
        async with self._db.execute(
            "SELECT id, login_key FROM users WHERE id = ?", (user_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            raise NotFound(f"user not found: {user_id}")
        return AdminUser(id=row[0], login_key=row[1])

    async def _declared_column(self, connection_id: int, schema: str, table: str) -> str | None:
        async with self._db.execute(
            "SELECT column_name FROM row_policies "
            "WHERE connection_id = ? AND schema_name = ? AND table_name = ?",
            (connection_id, schema, table),
        ) as cur:
            row = await cur.fetchone()
        return None if row is None else row[0]

    async def _group_rules(self, group: str) -> list[Tuple]:
        """Every reader tuple held by the group (db_schema, db_table and row_set).

        The store can only list by object type for row_set, so this reads everything
        and filters by the group userset.
        """
        userset = ids.group_member(group)
        return [t for t in await self._store.read() if t.user == userset and t.relation == "reader"]

    async def _table_row_sets(self, connection: str, schema: str, table: str) -> list[Tuple]:
        """Row_set reader tuples (any group) on one table."""
        found = []
        for t in await self._store.read():
            if t.relation != "reader" or not t.object.startswith("row_set:"):
                continue
            ref = ids.parse_row_set(t.object)
            if (ref.connection, ref.schema, ref.table) == (connection, schema, table):
                found.append(t)
        return found

    # --- writes --------------------------------------------------------------------

    async def _write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
        """Write to OpenFGA, batching deletes beyond one request's tuple limit."""
        writes, deletes = list(writes), list(deletes)
        if len(writes) + len(deletes) <= MAX_TUPLES_PER_WRITE:
            await self._store.write(writes, deletes)
            return
        if writes:
            raise ValueError("too many tuples in one write")
        for i in range(0, len(deletes), MAX_TUPLES_PER_WRITE):
            await self._store.write((), deletes[i : i + MAX_TUPLES_PER_WRITE])

    async def _record(
        self,
        actor: AdminUser,
        action: str,
        args: dict[str, Any],
        *,
        connection_id: int | None = None,
        written: Sequence[Tuple] = (),
        deleted: Sequence[Tuple] = (),
        error: str | None = None,
        failed: dict[str, str] | None = None,
    ) -> None:
        async with metadata.transaction(self._db):
            await self._audit(
                actor, action, args, connection_id, written, deleted, error=error, failed=failed
            )

    async def _audit(
        self,
        actor: AdminUser,
        action: str,
        args: dict[str, Any],
        connection_id: int | None,
        written: Sequence[Tuple] = (),
        deleted: Sequence[Tuple] = (),
        *,
        error: str | None = None,
        failed: dict[str, str] | None = None,
    ) -> None:
        """Insert the audit row; the caller holds the SQLite transaction."""
        detail: dict[str, Any] = {
            "action": action,
            **args,
            "written": _tuples(written),
            "deleted": _tuples(deleted),
        }
        if failed:
            detail["failed_connections"] = failed
        if error is not None:
            detail["error"] = error
        await audit.record(
            self._db,
            "admin",
            user_id=actor.id,
            connection_id=connection_id,
            error=error,
            detail=detail,
        )

    async def _apply_everywhere(self, connections: Sequence[str], op: PgOp) -> dict[str, str]:
        """Run one op on every connection; a failing connection is reported, not raised."""
        failed: dict[str, str] = {}
        for connection in connections:
            try:
                await self._executor.apply(connection, [op])
            except Exception as exc:
                failed[connection] = f"{type(exc).__name__}: {exc}"
        return failed

    # --- groups --------------------------------------------------------------------

    async def create_group(
        self, actor: AdminUser, name: str, description: str | None = None
    ) -> dict[str, str]:
        """Create the group and its ``g_`` role on every connection.

        Returns the connections whose role creation failed (name -> error); the group
        exists regardless and the Reconciler recreates the missing roles.
        """
        if not _GROUP_NAME.fullmatch(name):
            raise ValueError(f"invalid group name: {name!r}")
        async with self._lock:
            async with self._db.execute("SELECT 1 FROM groups WHERE name = ?", (name,)) as cur:
                if await cur.fetchone() is not None:
                    raise RuleConflict(f"group already exists: {name}")
            async with metadata.transaction(self._db):
                await self._db.execute(
                    "INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?)",
                    (name, description, metadata.now_iso()),
                )
            failed = await self._apply_everywhere(
                list(await self._connections()), CreateGroupRole(group_role(name))
            )
            await self._record(
                actor,
                "create_group",
                {"name": name, "description": description},
                failed=failed,
            )
            return failed

    async def delete_group(self, actor: AdminUser, name: str) -> dict[str, str]:
        """Delete a group with no rules left; returns connections where DROP ROLE failed."""
        async with self._lock:
            await self._require_group(name)
            rules = await self._group_rules(name)
            if rules:
                held = ", ".join(f"{t.object}#{t.relation}" for t in rules)
                raise RuleConflict(f"group {name} still has rules: {held}")
            members = await self._store.read(ids.group(name), "member")
            await self._write(deletes=members)
            async with metadata.transaction(self._db):
                await self._db.execute("DELETE FROM groups WHERE name = ?", (name,))
            failed = await self._apply_everywhere(
                list(await self._connections()), DropGroupRole(group_role(name))
            )
            await self._record(
                actor, "delete_group", {"name": name}, deleted=members, failed=failed
            )
            return failed

    async def add_member(self, actor: AdminUser, group: str, user_id: int) -> None:
        await self._member(actor, "add_member", group, user_id)

    async def remove_member(self, actor: AdminUser, group: str, user_id: int) -> None:
        await self._member(actor, "remove_member", group, user_id)

    async def _member(self, actor: AdminUser, action: str, group: str, user_id: int) -> None:
        async with self._lock:
            await self._require_group(group)
            await self._user(user_id)
            member = Tuple(ids.user(user_id), "member", ids.group(group))
            adding = action == "add_member"
            written, deleted = ([member], []) if adding else ([], [member])
            await self._write(written, deleted)
            await self._record(
                actor,
                action,
                {"group": group, "user_id": user_id},
                written=written,
                deleted=deleted,
            )

    # --- schema and table readers ----------------------------------------------------

    async def grant_schema_reader(
        self, actor: AdminUser, group: str, connection: str, schema: str
    ) -> None:
        _no_wildcard("schema name", schema)
        async with self._lock:
            await self._require_group(group)
            connection_id = await self._connection_id(connection)
            for t in await self._group_rules(group):
                if t.object.startswith("db_table:"):
                    ref = ids.parse_db_table(t.object)
                    if (ref.connection, ref.schema) == (connection, schema):
                        raise RuleConflict(
                            f"group {group} already reads table {ref.table} in "
                            f"{connection}/{schema}; remove the table rules first"
                        )
            rule = Tuple(ids.group_member(group), "reader", ids.db_schema(connection, schema))
            await self._write([rule])
            await self._record(
                actor,
                "grant_schema_reader",
                {"group": group, "connection": connection, "schema": schema},
                connection_id=connection_id,
                written=[rule],
            )

    async def revoke_schema_reader(
        self, actor: AdminUser, group: str, connection: str, schema: str
    ) -> None:
        _no_wildcard("schema name", schema)
        async with self._lock:
            await self._require_group(group)
            connection_id = await self._connection_id(connection)
            rule = Tuple(ids.group_member(group), "reader", ids.db_schema(connection, schema))
            await self._write(deletes=[rule])
            await self._record(
                actor,
                "revoke_schema_reader",
                {"group": group, "connection": connection, "schema": schema},
                connection_id=connection_id,
                deleted=[rule],
            )

    async def grant_table_reader(
        self, actor: AdminUser, group: str, connection: str, schema: str, table: str
    ) -> None:
        _no_wildcard("schema name", schema)
        _no_wildcard("table name", table)
        async with self._lock:
            await self._require_group(group)
            connection_id = await self._connection_id(connection)
            schema_rule = Tuple(
                ids.group_member(group), "reader", ids.db_schema(connection, schema)
            )
            if schema_rule in await self._group_rules(group):
                raise RuleConflict(
                    f"group {group} already reads the whole schema {connection}/{schema}; "
                    "remove the schema rule first"
                )
            rule = Tuple(ids.group_member(group), "reader", ids.db_table(connection, schema, table))
            await self._write([rule])
            await self._record(
                actor,
                "grant_table_reader",
                {"group": group, "connection": connection, "schema": schema, "table": table},
                connection_id=connection_id,
                written=[rule],
            )

    async def revoke_table_reader(
        self, actor: AdminUser, group: str, connection: str, schema: str, table: str
    ) -> None:
        _no_wildcard("schema name", schema)
        _no_wildcard("table name", table)
        async with self._lock:
            await self._require_group(group)
            connection_id = await self._connection_id(connection)
            rule = Tuple(ids.group_member(group), "reader", ids.db_table(connection, schema, table))
            await self._write(deletes=[rule])
            await self._record(
                actor,
                "revoke_table_reader",
                {"group": group, "connection": connection, "schema": schema, "table": table},
                connection_id=connection_id,
                deleted=[rule],
            )

    # --- row sets --------------------------------------------------------------------

    async def grant_row_set(
        self,
        actor: AdminUser,
        group: str,
        connection: str,
        schema: str,
        table: str,
        column: str,
        value: str,
    ) -> None:
        await self._row_set(actor, "grant_row_set", group, connection, schema, table, column, value)

    async def revoke_row_set(
        self,
        actor: AdminUser,
        group: str,
        connection: str,
        schema: str,
        table: str,
        column: str,
        value: str,
    ) -> None:
        await self._row_set(
            actor, "revoke_row_set", group, connection, schema, table, column, value
        )

    async def _row_set(
        self,
        actor: AdminUser,
        action: str,
        group: str,
        connection: str,
        schema: str,
        table: str,
        column: str,
        value: str,
    ) -> None:
        _no_wildcard("schema name", schema)
        _no_wildcard("table name", table)
        _no_wildcard("row_set column", column)
        _no_wildcard("row_set value", value)
        async with self._lock:
            await self._require_group(group)
            connection_id = await self._connection_id(connection)
            declared = await self._declared_column(connection_id, schema, table)
            if declared is None:
                raise RuleConflict(
                    f"{connection}/{schema}.{table} is not declared as row-controlled"
                )
            if declared != column:
                raise RuleConflict(
                    f"{connection}/{schema}.{table} is row-controlled by column {declared}, "
                    f"not {column}"
                )
            set_id = ids.row_set(connection, schema, table, column, value)
            rule = Tuple(ids.group_member(group), "reader", set_id)
            parent = Tuple(ids.db_table(connection, schema, table), "table", set_id)
            readers = set(await self._store.read(set_id, "reader"))
            written: list[Tuple] = []
            deleted: list[Tuple] = []
            if action == "grant_row_set":
                written.append(rule)
                if not readers:
                    written.append(parent)
            else:
                deleted.append(rule)
                if not readers - {rule}:
                    deleted.append(parent)
            await self._write(written, deleted)
            await self._record(
                actor,
                action,
                {
                    "group": group,
                    "connection": connection,
                    "schema": schema,
                    "table": table,
                    "column": column,
                    "value": value,
                },
                connection_id=connection_id,
                written=written,
                deleted=deleted,
            )

    # --- row-control declarations ------------------------------------------------------

    async def declare_row_policy(
        self, actor: AdminUser, connection: str, schema: str, table: str, column: str
    ) -> None:
        _no_wildcard("schema name", schema)
        _no_wildcard("table name", table)
        _no_wildcard("row_set column", column)
        args = {"connection": connection, "schema": schema, "table": table, "column": column}
        async with self._lock:
            connection_id = await self._connection_id(connection)
            declared = await self._declared_column(connection_id, schema, table)
            if declared is not None:
                raise RuleConflict(
                    f"{connection}/{schema}.{table} is already row-controlled by column {declared}"
                )
            distinct = await self._stats.distinct_count(
                connection, schema, table, column, self._distinct_limit
            )
            if distinct > self._distinct_limit:
                raise RuleConflict(
                    f"column {column} has more than {self._distinct_limit} distinct values"
                )
            async with metadata.transaction(self._db):
                await self._db.execute(
                    "INSERT INTO row_policies "
                    "(connection_id, schema_name, table_name, column_name, enabled_by, enabled_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (connection_id, schema, table, column, actor.id, metadata.now_iso()),
                )
            try:
                skipped = await self._executor.apply(
                    connection,
                    [t.op for t in row_policy_enable_ops(connection, schema, table, column)],
                )
                if skipped:
                    # The table, its schema or gw_managed is missing: nothing was enabled.
                    raise NotFound(
                        f"{connection}/{schema}.{table}: row control was not enabled "
                        "(table, schema or gw_managed missing)"
                    )
            except Exception as exc:
                async with metadata.transaction(self._db):
                    await self._db.execute(
                        "DELETE FROM row_policies "
                        "WHERE connection_id = ? AND schema_name = ? AND table_name = ?",
                        (connection_id, schema, table),
                    )
                    await self._audit(
                        actor,
                        "declare_row_policy",
                        args,
                        connection_id,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                raise
            await self._record(actor, "declare_row_policy", args, connection_id=connection_id)

    async def undeclare_row_policy(
        self, actor: AdminUser, connection: str, schema: str, table: str
    ) -> None:
        _no_wildcard("schema name", schema)
        _no_wildcard("table name", table)
        args = {"connection": connection, "schema": schema, "table": table}
        async with self._lock:
            connection_id = await self._connection_id(connection)
            if await self._declared_column(connection_id, schema, table) is None:
                raise NotFound(f"{connection}/{schema}.{table} is not row-controlled")
            readers = await self._table_row_sets(connection, schema, table)
            if readers:
                held = ", ".join(sorted(f"{t.object}#{t.relation}" for t in readers))
                raise RuleConflict(
                    f"{connection}/{schema}.{table} still has row_set readers: {held}"
                )
            try:
                await self._executor.apply(
                    connection, [t.op for t in row_policy_disable_ops(connection, schema, table)]
                )
            except Exception as exc:
                await self._record(
                    actor,
                    "undeclare_row_policy",
                    args,
                    connection_id=connection_id,
                    error=f"{type(exc).__name__}: {exc}",
                )
                raise
            async with metadata.transaction(self._db):
                await self._db.execute(
                    "DELETE FROM row_policies "
                    "WHERE connection_id = ? AND schema_name = ? AND table_name = ?",
                    (connection_id, schema, table),
                )
                await self._audit(actor, "undeclare_row_policy", args, connection_id)

    # --- admins ----------------------------------------------------------------------

    async def add_admin(self, actor: AdminUser, user_id: int) -> None:
        async with self._lock:
            checker = AdminChecker(self._store, self._initial_admins)
            ensure_can_add_admin(await checker.is_admin(actor))
            await self._user(user_id)
            rule = admin_tuple(user_id)
            await self._write([rule])
            await self._record(actor, "add_admin", {"user_id": user_id}, written=[rule])

    async def remove_admin(self, actor: AdminUser, user_id: int) -> None:
        async with self._lock:
            target = await self._user(user_id)
            ensure_can_remove_admin(actor, target, self._initial_admins)
            rule = admin_tuple(user_id)
            await self._write(deletes=[rule])
            await self._record(actor, "remove_admin", {"user_id": user_id}, deleted=[rule])
