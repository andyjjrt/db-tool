"""Admin-side writes to the permission model, with the write-time checks of plan §2.4.

``RuleService`` is the layer behind the admin API: groups, members, table / schema /
row rules, row-control declarations and admins. Every mutating method holds one lock
across "check -> write", so two admins writing at once cannot both pass a check that
only one of them may pass. The lock is per instance; the application builds exactly one
``RuleService`` per process, which makes it the global lock of §2.4.

Each mutating method writes exactly one ``audit_log`` row of kind ``admin`` when it
completes (including a PG step that failed after the SQLite/OpenFGA part was done); a
call rejected by a check writes nothing. Store writes precede the SQLite transaction,
so a failed SQLite write can leave a permission change without its admin audit row.
Group deletion records its admin write
before inline work; inline failures get a separate ``sync`` row from the Syncer
because the audit log is append-only. The ``detail`` JSON carries the action, its
arguments, the tuples written and deleted and, on a PG failure, ``error``.

Row control is declared in OpenFGA, which is its single source of truth: one
``Tuple(column:<col>, row_column, db_table:<conn>/<schema>/<table>)`` per controlled
table. A row_set exists iff its parent tuple ``db_table#table -> row_set`` exists;
``RuleService`` maintains those parent tuples. Who enabled a table, and when, lives only
in the audit log. Groups exist only through ``gateway:main#group@group:<name>``;
SQLite descriptions are display-only, and group roles follow the tuple change stream.

Errors: ``RuleConflict`` (409), ``NotFound`` (404), ``AdminForbidden`` (403) and
``InvalidInput`` for invalid input (422).
"""

import asyncio
import re
from collections.abc import Collection, Sequence
from dataclasses import asdict, dataclass
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
from db_gateway.permissions.context import ConnectionLocks, TargetUnavailable, safe_error
from db_gateway.permissions.executor import ApplyError
from db_gateway.permissions.executor_protocol import Executor
from db_gateway.permissions.ids import InvalidInput
from db_gateway.permissions.scan import UnsafeView
from db_gateway.permissions.store import MAX_TUPLES_PER_WRITE, PermissionStore, Tuple
from db_gateway.permissions.types import (
    ALL,
    DisableRowPolicy,
    EnableRowPolicy,
)

__all__ = [
    "AdminForbidden",
    "GroupInfo",
    "NotFound",
    "PartitionStats",
    "RuleConflict",
    "RuleService",
    "TargetUnavailable",
]

_GROUP_NAME = re.compile(r"[a-z][a-z0-9_]{0,40}")


class RuleConflict(Exception):
    """The write conflicts with an existing rule or state; the API maps it to 409."""

    def __init__(self, message: str, conflicts: Sequence[Tuple | UnsafeView] = ()) -> None:
        super().__init__(message)
        self.conflicts = [asdict(item) for item in conflicts]


class NotFound(Exception):
    """A named group, connection, user or declaration does not exist; the API maps it to 404."""


@dataclass(frozen=True, slots=True)
class GroupInfo:
    name: str
    description: str | None


class PartitionStats(Protocol):
    async def distinct_count(
        self, connection: str, schema: str, table: str, column: str, limit: int
    ) -> int:
        """Number of distinct values of the column; may stop counting at limit + 1."""
        ...


class Scanner(Protocol):
    async def unsafe_views(
        self, connection: str, tables: Collection[tuple[str, str]]
    ) -> list[UnsafeView]: ...


def controlled_tables(tuples: Collection[Tuple], connection: str) -> set[tuple[str, str]]:
    tables = set()
    for rule in tuples:
        if rule.relation == "row_column" and rule.object.startswith("db_table:"):
            ref = ids.parse_db_table(rule.object)
            if ref.connection == connection:
                tables.add((ref.schema, ref.table))
    return tables


def readable_rules(view: UnsafeView, tuples: Collection[Tuple], connection: str) -> list[Tuple]:
    objects = {
        ids.db_table(connection, view.schema, view.name),
        ids.db_schema(connection, view.schema),
    }
    return [
        rule
        for rule in tuples
        if rule.relation == "reader"
        and rule.object in objects
        and rule.user.startswith("group:")
        and rule.user.endswith("#member")
    ]


class InlineRevoker(Protocol):
    async def apply_inline(self, deletes: Sequence[Tuple], timeout_s: float) -> bool: ...


def _no_wildcard(what: str, value: str) -> None:
    if value == ALL:
        raise InvalidInput(f"'*' is not a legal {what}")


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
        initial_admins: Collection[str] = INITIAL_ADMINS,
        inline: InlineRevoker | None = None,
        revoke_timeout_s: float = 5.0,
        locks: ConnectionLocks | None = None,
        scanner: Scanner | None = None,
    ) -> None:
        self._db = db
        self._store = store
        self._executor = executor
        self._stats = partition_stats
        self._distinct_limit = distinct_limit
        self._initial_admins = initial_admins
        self._inline = inline
        self._revoke_timeout = revoke_timeout_s
        self._lock = asyncio.Lock()
        self._locks = locks if locks is not None else ConnectionLocks()
        self._scanner = scanner

    @property
    def lock(self) -> asyncio.Lock:
        """The instance-wide permission-write lock of plan §2.4.

        Every admin mutation holds it across its permission-store check and its
        write. The admin user routes (disable, unbind) hold it too, so an admin
        promotion or removal cannot interleave between a route's target-admin
        check and its metadata write (gate finding M3).
        """
        return self._lock

    # --- lookups -------------------------------------------------------------------

    async def _connection_id(self, name: str) -> int:
        async with self._db.execute("SELECT id FROM connections WHERE name = ?", (name,)) as cur:
            row = await cur.fetchone()
        if row is None:
            raise NotFound(f"connection not found: {name}")
        return row[0]

    async def _require_group(self, name: str) -> None:
        if not await self._store.read(ids.GATEWAY_MAIN, "group", ids.group(name)):
            raise NotFound(f"group not found: {name}")

    async def _user(self, user_id: int) -> AdminUser:
        async with self._db.execute(
            "SELECT id, login_key FROM users WHERE id = ?", (user_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            raise NotFound(f"user not found: {user_id}")
        return AdminUser(id=row[0], login_key=row[1])

    async def _row_column_tuple(self, connection: str, schema: str, table: str) -> Tuple | None:
        found = await self._store.read(
            object=ids.db_table(connection, schema, table), relation="row_column"
        )
        return found[0] if found else None

    async def _declared_column(self, connection: str, schema: str, table: str) -> str | None:
        found = await self._row_column_tuple(connection, schema, table)
        return None if found is None else ids.parse_column(found.user)

    async def _group_rules(self, group: str) -> list[Tuple]:
        """Every reader tuple held by the group (db_schema, db_table and row_set).

        The store can only list by object type for row_set, so this reads everything
        and filters by the group userset.
        """
        userset = ids.group_member(group)
        return [t for t in await self._store.read() if t.user == userset and t.relation == "reader"]

    async def _table_row_sets(self, connection: str, schema: str, table: str) -> list[Tuple]:
        """Parent tuples of the row_sets of one table; a row_set exists iff its parent does."""
        return await self._store.read(
            object="row_set:", user=ids.db_table(connection, schema, table)
        )

    async def _unsafe_views(
        self, connection: str, *, declaring: tuple[str, str] | None = None
    ) -> tuple[list[UnsafeView], list[Tuple]]:
        if self._scanner is None:
            return [], []
        tuples = await self._store.read()
        tables = controlled_tables(tuples, connection)
        if declaring is not None:
            tables.add(declaring)
        return await self._scanner.unsafe_views(connection, tables), tuples

    def _refuse_unsafe(self, views: Sequence[UnsafeView], rules: Sequence[Tuple] = ()) -> None:
        if views:
            names = ", ".join(f"{v.schema}.{v.name} ({v.reason})" for v in views)
            raise RuleConflict(f"unsafe relations: {names}", [*views, *rules])

    # --- writes --------------------------------------------------------------------

    async def _inline_revoke(self, deleted: Sequence[Tuple]) -> str:
        if self._inline is not None and await self._inline.apply_inline(
            deleted, self._revoke_timeout
        ):
            return "synced"
        return "pending"

    async def _write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
        """Write to OpenFGA, batching deletes beyond one request's tuple limit."""
        writes, deletes = list(writes), list(deletes)
        if len(writes) + len(deletes) <= MAX_TUPLES_PER_WRITE:
            await self._store.write(writes, deletes)
            return
        if writes:
            raise InvalidInput("too many tuples in one write")
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

    # --- groups --------------------------------------------------------------------

    async def create_group(
        self, actor: AdminUser, name: str, description: str | None = None
    ) -> None:
        """Create the group tuple; the Syncer creates its role on every connection."""
        if not _GROUP_NAME.fullmatch(name):
            raise InvalidInput(f"invalid group name: {name!r}")
        async with self._lock:
            rule = ids.group_tuple(name)
            if await self._store.read(rule.object, rule.relation, rule.user):
                raise RuleConflict(f"group already exists: {name}", [rule])
            await self._write([rule])
            async with metadata.transaction(self._db):
                if description is not None:
                    await self._set_description(rule.user, description)
                await self._audit(
                    actor,
                    "create_group",
                    {"name": name, "description": description},
                    None,
                    written=[rule],
                )

    async def _set_description(self, object_id: str, description: str | None) -> None:
        """Update display text; the caller holds the SQLite transaction."""
        if description is None:
            await self._db.execute("DELETE FROM descriptions WHERE object = ?", (object_id,))
        else:
            await self._db.execute(
                "INSERT INTO descriptions (object, description, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(object) DO UPDATE SET "
                "description = excluded.description, updated_at = excluded.updated_at",
                (object_id, description, metadata.now_iso()),
            )

    async def set_description(
        self, actor: AdminUser, object_id: str, description: str | None
    ) -> None:
        """Set display-only text for an OpenFGA object, or remove it with None."""
        if len(object_id) > ids.MAX_OBJECT_LEN or "#" in object_id:
            raise InvalidInput(f"invalid object id: {object_id!r}")
        match object_id.partition(":")[0]:
            case "user":
                ids.parse_user(object_id)
            case "group":
                ids.parse_group(object_id)
            case "column":
                ids.parse_column(object_id)
            case "gateway":
                if object_id != ids.GATEWAY_MAIN:
                    raise InvalidInput(f"invalid gateway id: {object_id!r}")
            case "db_schema":
                ids.parse_db_schema(object_id)
            case "db_table":
                ids.parse_db_table(object_id)
            case "row_set":
                ids.parse_row_set(object_id)
            case _:
                raise InvalidInput(f"unknown object type: {object_id!r}")
        async with self._lock:
            async with metadata.transaction(self._db):
                await self._set_description(object_id, description)
                await self._audit(
                    actor,
                    "set_description",
                    {"object_id": object_id, "description": description},
                    None,
                )

    async def list_groups(self) -> list[GroupInfo]:
        """List existing groups sorted by name, with optional SQLite display text."""
        groups = await self._store.read(ids.GATEWAY_MAIN, "group")
        async with self._db.execute("SELECT object, description FROM descriptions") as cur:
            descriptions: dict[str, str] = {row[0]: row[1] for row in await cur.fetchall()}
        return sorted(
            (GroupInfo(ids.parse_group(t.user), descriptions.get(t.user)) for t in groups),
            key=lambda group: group.name,
        )

    async def delete_group(self, actor: AdminUser, name: str) -> str:
        """Delete a rule-free group and inline revoke its members before dropping its role."""
        async with self._lock:
            await self._require_group(name)
            rules = await self._group_rules(name)
            if rules:
                held = ", ".join(f"{t.object}#{t.relation}" for t in rules)
                raise RuleConflict(f"group {name} still has rules: {held}", rules)
            members = await self._store.read(ids.group(name), "member")
            deleted = [*members, ids.group_tuple(name)]
            # Batch members first; only the final batch removes group existence.
            removed: list[Tuple] = []
            try:
                for i in range(0, len(deleted), MAX_TUPLES_PER_WRITE):
                    batch = deleted[i : i + MAX_TUPLES_PER_WRITE]
                    await self._write(deletes=batch)
                    removed.extend(batch)
            except Exception as exc:
                if removed:
                    await self._record(
                        actor,
                        "delete_group",
                        {"name": name},
                        deleted=removed,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    await self._inline_revoke(removed)
                raise
            async with metadata.transaction(self._db):
                await self._set_description(ids.group(name), None)
                await self._audit(actor, "delete_group", {"name": name}, None, deleted=deleted)
            return await self._inline_revoke(deleted)

    async def add_member(self, actor: AdminUser, group: str, user_id: int) -> None:
        await self._member(actor, "add_member", group, user_id)

    async def remove_member(self, actor: AdminUser, group: str, user_id: int) -> str:
        return await self._member(actor, "remove_member", group, user_id)

    async def _member(self, actor: AdminUser, action: str, group: str, user_id: int) -> str:
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
            return "synced" if adding else await self._inline_revoke(deleted)

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
                            f"{connection}/{schema}; remove the table rules first",
                            [t],
                        )
            views, _ = await self._unsafe_views(connection)
            self._refuse_unsafe([v for v in views if v.schema == schema])
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
    ) -> str:
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
            return await self._inline_revoke([rule])

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
                    "remove the schema rule first",
                    [schema_rule],
                )
            views, _ = await self._unsafe_views(connection)
            self._refuse_unsafe([v for v in views if (v.schema, v.name) == (schema, table)])
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
    ) -> str:
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
            return await self._inline_revoke([rule])

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
    ) -> str:
        return await self._row_set(
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
    ) -> str:
        _no_wildcard("schema name", schema)
        _no_wildcard("table name", table)
        _no_wildcard("row_set column", column)
        _no_wildcard("row_set value", value)
        async with self._lock:
            await self._require_group(group)
            connection_id = await self._connection_id(connection)
            declared = await self._declared_column(connection, schema, table)
            if declared is None:
                raise RuleConflict(
                    f"{connection}/{schema}.{table} is not declared as row-controlled"
                )
            if declared != column:
                raise RuleConflict(
                    f"{connection}/{schema}.{table} is row-controlled by column {declared}, "
                    f"not {column}",
                    [
                        Tuple(
                            ids.column(declared),
                            "row_column",
                            ids.db_table(connection, schema, table),
                        )
                    ],
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
            return await self._inline_revoke(deleted) if action == "revoke_row_set" else "synced"

    # --- row-control declarations ------------------------------------------------------

    async def declare_row_policy(
        self, actor: AdminUser, connection: str, schema: str, table: str, column: str
    ) -> None:
        _no_wildcard("schema name", schema)
        _no_wildcard("table name", table)
        _no_wildcard("row_set column", column)
        args = {"connection": connection, "schema": schema, "table": table, "column": column}
        async with self._lock, self._locks(connection):
            connection_id = await self._connection_id(connection)
            declared = await self._declared_column(connection, schema, table)
            if declared is not None:
                raise RuleConflict(
                    f"{connection}/{schema}.{table} is already row-controlled by column {declared}",
                    [
                        Tuple(
                            ids.column(declared),
                            "row_column",
                            ids.db_table(connection, schema, table),
                        )
                    ],
                )
            views, tuples = await self._unsafe_views(connection, declaring=(schema, table))
            exposed = [v for v in views if readable_rules(v, tuples, connection)]
            self._refuse_unsafe(
                exposed, [rule for v in exposed for rule in readable_rules(v, tuples, connection)]
            )
            distinct = await self._stats.distinct_count(
                connection, schema, table, column, self._distinct_limit
            )
            if distinct > self._distinct_limit:
                raise RuleConflict(
                    f"column {column} has more than {self._distinct_limit} distinct values"
                )
            rule = Tuple(ids.column(column), "row_column", ids.db_table(connection, schema, table))
            try:
                skipped = await self._executor.apply(
                    connection, [EnableRowPolicy(schema, table, column)]
                )
                if skipped:
                    # The table, its schema or gw_managed is missing: nothing was enabled.
                    raise NotFound(
                        f"{connection}/{schema}.{table}: row control was not enabled "
                        "(table, schema or gw_managed missing)"
                    )
            except Exception as exc:
                await self._record(
                    actor,
                    "declare_row_policy",
                    args,
                    connection_id=connection_id,
                    error=safe_error(exc),
                )
                if isinstance(exc, ApplyError) and isinstance(exc.original, TargetUnavailable):
                    raise exc.original from None
                raise
            try:
                await self._write([rule])
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                try:
                    if await self._executor.apply(connection, [DisableRowPolicy(schema, table)]):
                        error += "; undo skipped: RLS may still be enabled"
                except Exception as undo_exc:
                    error += f"; undo failed: {safe_error(undo_exc)}"
                await self._record(
                    actor, "declare_row_policy", args, connection_id=connection_id, error=error
                )
                raise
            await self._record(
                actor, "declare_row_policy", args, connection_id=connection_id, written=[rule]
            )

    async def undeclare_row_policy(
        self, actor: AdminUser, connection: str, schema: str, table: str
    ) -> str | None:
        """Remove the declaration; returns None, or the error if disabling RLS is pending.

        The ``row_column`` tuple is deleted first and stays deleted when the PG step
        fails or is skipped: the Syncer applies the same op from the change stream.
        """
        _no_wildcard("schema name", schema)
        _no_wildcard("table name", table)
        args = {"connection": connection, "schema": schema, "table": table}
        async with self._lock, self._locks(connection):
            connection_id = await self._connection_id(connection)
            rule = await self._row_column_tuple(connection, schema, table)
            if rule is None:
                raise NotFound(f"{connection}/{schema}.{table} is not row-controlled")
            readers = await self._table_row_sets(connection, schema, table)
            if readers:
                held = ", ".join(sorted(t.object for t in readers))
                raise RuleConflict(
                    f"{connection}/{schema}.{table} still has row_set readers: {held}", readers
                )
            await self._write(deletes=[rule])
            error: str | None = None
            try:
                skipped = await self._executor.apply(connection, [DisableRowPolicy(schema, table)])
                if skipped:
                    error = f"{connection}/{schema}.{table}: row control was not disabled (skipped)"
            except Exception as exc:
                error = safe_error(exc)
            await self._record(
                actor,
                "undeclare_row_policy",
                args,
                connection_id=connection_id,
                deleted=[rule],
                error=error,
            )
            return error

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
            if not await self._store.read(rule.object, rule.relation, rule.user):
                raise NotFound(f"user is not an admin: {user_id}")
            await self._write(deletes=[rule])
            await self._record(actor, "remove_admin", {"user_id": user_id}, deleted=[rule])
