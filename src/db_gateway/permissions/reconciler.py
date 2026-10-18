"""Full comparison of the OpenFGA tuples with one target database (plan §2.1, §2.7, §10).

The expected PG state is the union of ``grant_ops`` of every tuple (restricted to the
connection) plus a ``g_<name>`` role for every SQLite group. ``diff`` compares it with the
``ActualState`` and returns the fixes and the report-only findings; it is a pure function.
``Reconciler.reconcile`` runs the whole unit (read tuples, read the catalog, diff, apply,
audit) under ``locks(connection)``, so the Syncer and inline revokes never interleave.

Scope: only grantees and members named ``g_*``, ``u_*`` and ``gw_managed`` are looked at, in
every non-system schema of the target DB (``pg_catalog``, ``information_schema``,
``pg_toast*``, ``pg_temp*``, ``gateway_acl`` and ``paradedb`` are excluded).

Fixed (applied unless ``dry_run``):
  - a SQLite group without its ``g_<name>`` role: ``CreateGroupRole``;
  - missing expected table SELECT, default privileges, ``row_grants`` rows and memberships:
    the grant op; present but unexpected ones for ``g_*`` grantees, ``row_grants`` rows and
    ``u_*`` memberships in ``g_*`` roles granted only by the admin account: the inverse op;
    every ``row_grants`` row (any ``group_role``) that no tuple expects: ``DeleteRowGrant``;
    a required membership without an ``inherit_option`` row: ``GrantMembership``;
  - a ``db_table#row_column`` table whose RLS is not enabled and forced, lacks a ``gw_*``
    policy or has a wrong policy definition, or whose ``gw_managed`` SELECT is gone:
    ``EnableRowPolicy``.
Ops the executor would skip (the role or table they name does not exist, e.g. a personal role
that is created at the user's first session) are not planned, so they never show up as drift.

Reported only, never changed: ``gw_*`` policies on a table with no ``row_column`` tuple,
other permissive policies on a row-controlled table,
``g_*`` roles without a SQLite group, a schema with rules where ``gw_managed`` lacks USAGE
(operator setup), a ``u_*`` membership in a ``g_*`` role granted by another role than the
admin account (never revoked), ``u_*`` roles that are not members of ``gw_managed``, SELECT on
a table granted directly to ``gw_managed`` / ``u_*`` without a declaration, tuples the mapping
rejects, a declared table that does not exist and two ``row_column`` tuples on one table.

Applying: one ``executor.apply`` call per fix kind (op class), in a fixed order (roles,
row_grants deletes, revokes, grants, row_grants upserts, RLS). A kind that fails is reported
in ``error`` / ``failed`` and does not stop the others; the next run retries it. An audit row
of kind ``sync`` is written when at least one fix was applied and ``dry_run`` is false.
"""

import asyncio
import logging
import re
from collections import defaultdict
from collections.abc import Awaitable, Callable, Collection, Mapping, Sequence
from dataclasses import asdict, dataclass, field

import aiosqlite
import psycopg
from psycopg.sql import SQL, Literal

from db_gateway import metadata
from db_gateway.metadata import audit
from db_gateway.permissions.actual import ActualState, RowPolicy, read_actual
from db_gateway.permissions.context import (
    ConnectionInfo,
    ConnectionLocks,
    load_connection,
    load_connections,
    mapping_context,
)
from db_gateway.permissions.executor_protocol import Executor
from db_gateway.permissions.mapping import grant_ops
from db_gateway.permissions.store import PermissionStore, Tuple
from db_gateway.permissions.types import (
    GW_MANAGED,
    CreateGroupRole,
    DeleteRowGrant,
    EnableRowPolicy,
    GrantAllTablesSelect,
    GrantDefaultSelect,
    GrantMembership,
    GrantTableSelect,
    MappingContext,
    PgOp,
    RevokeDefaultSelect,
    RevokeMembership,
    RevokeTableSelect,
    UpsertRowGrant,
    group_role,
)

logger = logging.getLogger(__name__)

_SYSTEM_SCHEMAS = ("pg_catalog", "information_schema", "gateway_acl", "paradedb")

# Application order of the fix kinds.
_ORDER: tuple[type[PgOp], ...] = (
    CreateGroupRole,
    DeleteRowGrant,
    RevokeMembership,
    RevokeTableSelect,
    RevokeDefaultSelect,
    GrantMembership,
    GrantAllTablesSelect,
    GrantTableSelect,
    GrantDefaultSelect,
    UpsertRowGrant,
    EnableRowPolicy,
)


class ReconcileFailed(Exception):
    """A strict reconcile ended with an error or with fixes that could not be applied."""

    def __init__(self, report: "ReconcileReport") -> None:
        super().__init__(
            f"reconcile of {report.connection} failed: "
            f"{report.error or f'{len(report.failed)} fixes failed'}"
        )
        self.report = report


@dataclass(frozen=True, slots=True)
class Drift:
    """A finding the Reconciler reports but never changes."""

    kind: str
    message: str


@dataclass(frozen=True, slots=True)
class Plan:
    fixes: list[PgOp]
    reported: list[Drift]


@dataclass(slots=True)
class ReconcileReport:
    connection: str
    dry_run: bool = False
    fixes: list[PgOp] = field(default_factory=list)
    reported: list[Drift] = field(default_factory=list)
    skipped: list[PgOp] = field(default_factory=list)
    failed: list[PgOp] = field(default_factory=list)
    error: str | None = None


# --- expected state (pure) ---


def expected_ops(
    tuples: Collection[Tuple], ctx: MappingContext, connection: str
) -> tuple[list[PgOp], list[Drift]]:
    """Union of ``grant_ops`` of all tuples for one connection; unmappable ones are reported."""
    ops: list[PgOp] = []
    reported: list[Drift] = []
    for item in sorted(tuples, key=lambda t: (t.object, t.relation, t.user)):
        try:
            targeted = grant_ops(item, ctx)
        except ValueError as exc:
            reported.append(
                Drift("invalid_tuple", f"{item.user} {item.relation} {item.object}: {exc}")
            )
            continue
        ops.extend(t.op for t in targeted if t.connection == connection)
    return ops, reported


# --- policy definitions ---

_GW_POLICIES = frozenset({"gw_passthrough", "gw_read"})


def _squash(text: str | None) -> str:
    """Drop SQL whitespace, but keep quoted identifiers and string literals byte for byte.

    Whitespace inside "..." or '...' is data (a column named "team " is not "team"), so
    only the formatting between tokens is normalised.
    """
    out: list[str] = []
    quote: str | None = None
    for ch in text or "":
        if quote is not None:
            out.append(ch)
            if ch == quote:
                quote = None  # a doubled quote re-opens on the next char, which is fine
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif not ch.isspace():
            out.append(ch)
    return "".join(out)


_SIMPLE_IDENT = re.compile(r"[a-z_][a-z0-9_$]*")


def _quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _quote_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def policy_ok(
    policy: RowPolicy | None, name: str, op: EnableRowPolicy, *, column_type: str | None
) -> bool:
    """Whether the live policy is exactly what ``EnableRowPolicy`` would create.

    The whole expression is compared (ignoring whitespace outside quotes) with the deparsed
    text of the generated policy; the accepted variations are the optional ``AS <name>``
    aliases of the sub-selects and an unquoted column when it is a simple identifier. The
    operand is the bare column for a ``text`` column and ``(col)::text`` for any other type
    (``column_type`` from ``actual``; None, a missing column, never matches). The text must
    come from ``actual.read_policies``, which deparses with search_path = pg_catalog, so a
    shadowing operator such as ``public.=`` prints as ``OPERATOR(public.=)`` and fails.
    Anything else, e.g. a trailing ``OR true`` or a look-alike column such as ``"team "``,
    fails and triggers a re-apply.
    """
    if policy is None or not policy.permissive or policy.roles != ("PUBLIC",):
        return False
    if policy.with_check is not None or policy.using is None:
        return False
    using = _squash(policy.using)
    if name == "gw_passthrough":
        return policy.command == "*" and using in {
            _squash(f"(NOT ( SELECT gateway_acl.is_managed(){alias}))")
            for alias in ("", " AS is_managed")
        }
    if policy.command != "r" or column_type is None:
        return False
    args = f"{_quote_literal(op.schema)}::name, {_quote_literal(op.table)}::name"
    expected: set[str] = set()
    for alias in (False, True):
        allow = f"gateway_acl.allow_all({args}){' AS allow_all' if alias else ''}"
        values = f"gateway_acl.allowed_values({args}){' AS allowed_values' if alias else ''}"
        columns = {_quote_ident(op.column)}
        if _SIMPLE_IDENT.fullmatch(op.column):
            columns.add(op.column)  # PG prints simple identifiers unquoted
        for column in columns:
            operand = column if column_type == "text" else f"({column})::text"
            expected.add(
                _squash(f"(( SELECT {allow}) OR ({operand} = ANY (( SELECT {values})::text[])))")
            )
    return using in expected


# --- diff (pure) ---


def diff(
    *,
    ops: Sequence[PgOp],
    groups: Collection[str],
    actual: ActualState,
    relations: Mapping[str, Collection[str]],
    schemas: Collection[str],
    admin: str,
) -> Plan:
    """Compare the expected ops and groups with the actual state.

    ``relations`` maps each schema to its tables, views, materialized views and foreign tables
    (what ``GRANT ... ON ALL TABLES IN SCHEMA`` covers); ``admin`` is the gateway's admin
    account (the grantor of every membership it makes).
    """
    fixes: list[PgOp] = []
    reported: list[Drift] = []
    schema_set = set(schemas)

    # roles
    roles = set(actual.roles)
    wanted_roles = {group_role(name) for name in groups}
    creates = [CreateGroupRole(role) for role in sorted(wanted_roles - roles)]
    fixes.extend(creates)
    roles_after = roles | wanted_roles
    reported.extend(
        Drift("unknown_group_role", f"role {role} has no group in SQLite")
        for role in sorted(r for r in roles if r.startswith("g_") and r not in wanted_roles)
    )

    # the expected state, from the ops
    members: set[tuple[str, str]] = set()
    all_readers: set[tuple[str, str]] = set()
    table_readers: set[tuple[str, str, str]] = set()
    defaults: set[tuple[str, str, str]] = set()
    row_rows: set[tuple[str, str, str, str, str]] = set()
    declared: dict[tuple[str, str], EnableRowPolicy] = {}
    rule_schemas: set[str] = set()
    for op in ops:
        match op:
            case GrantMembership(group=group, member=member):
                members.add((group, member))
            case GrantAllTablesSelect(schema=schema, role=role):
                all_readers.add((schema, role))
                rule_schemas.add(schema)
            case GrantTableSelect(schema=schema, table=table, role=role):
                table_readers.add((schema, table, role))
                rule_schemas.add(schema)
            case GrantDefaultSelect(owner=owner, schema=schema, role=role):
                defaults.add((owner, schema, role))
                rule_schemas.add(schema)
            case UpsertRowGrant(group_role=role, schema=schema, table=table, column=col, value=v):
                row_rows.add((role, schema, table, col, v))
                rule_schemas.add(schema)
            case EnableRowPolicy(schema=schema, table=table) as enable:
                rule_schemas.add(schema)
                first = declared.setdefault((schema, table), enable)
                if first != enable:
                    reported.append(
                        Drift(
                            "conflicting_row_column",
                            f"{schema}.{table} has row_column tuples for both "
                            f"{first.column!r} and {enable.column!r}; using {first.column!r}",
                        )
                    )
            case _:
                pass

    row_security = {(s, t): (enabled, forced) for s, t, enabled, forced in actual.row_security}
    policies = {(p.schema, p.table, p.name): p for p in actual.policies}
    column_types = {(s, t, c): kind for s, t, c, kind in actual.column_types}

    # table SELECT
    expected_select: set[tuple[str, str, str]] = set()
    for schema, role in all_readers:
        for table in relations.get(schema, ()):
            expected_select.add((schema, table, role))
    for schema, table, role in table_readers:
        if table in relations.get(schema, ()):
            expected_select.add((schema, table, role))
    rls_tables = {key for key in declared if key in row_security}
    expected_select.update((s, t, GW_MANAGED) for s, t in rls_tables)
    policy_tables = {(p.schema, p.table) for p in actual.policies if p.name in _GW_POLICIES}
    revoke_selects: list[PgOp] = []
    for schema, table, role in sorted(actual.table_select):
        if (schema, table, role) in expected_select:
            continue
        if role.startswith("g_"):
            revoke_selects.append(RevokeTableSelect(schema, table, role))
        elif (role == GW_MANAGED and (schema, table) not in policy_tables) or (
            role.startswith("u_")
        ):
            # gw_managed on a table with leftover gw_* policies is part of undeclared_policy
            reported.append(
                Drift(
                    "unexpected_grant",
                    f"{role} has SELECT on {schema}.{table} without a rule",
                )
            )
    fixes.extend(revoke_selects)
    grant_all: set[tuple[str, str]] = set()
    grant_tables: list[PgOp] = []
    for schema, table, role in sorted(expected_select - actual.table_select):
        if role == GW_MANAGED or role not in roles_after:
            continue  # gw_managed is restored by EnableRowPolicy below
        if (schema, role) in all_readers:
            grant_all.add((schema, role))
        else:
            grant_tables.append(GrantTableSelect(schema, table, role))

    # default privileges
    expected_defaults = {d for d in defaults if d[1] in schema_set}
    for owner, schema, role in sorted(actual.default_select - expected_defaults):
        if role.startswith("g_"):
            fixes.append(RevokeDefaultSelect(owner, schema, role))
        elif role == GW_MANAGED or role.startswith("u_"):
            reported.append(
                Drift(
                    "unexpected_grant",
                    f"{role} has default SELECT for {owner} in {schema} without a rule",
                )
            )
    grant_defaults: list[PgOp] = [
        GrantDefaultSelect(owner, schema, role)
        for owner, schema, role in sorted(expected_defaults - actual.default_select)
        if role in roles_after
    ]

    # row_grants: the whole table belongs to the gateway, whatever the role is called
    actual_rows = set(actual.row_grants)
    delete_keys: set[tuple[str, str, str, str]] = set()
    for row in actual_rows:
        if row[0] not in roles_after or row not in row_rows:
            delete_keys.add((row[0], row[1], row[2], row[4]))
    fixes.extend(DeleteRowGrant(*key) for key in sorted(delete_keys))
    upserts: list[PgOp] = [
        UpsertRowGrant(*row)
        for row in sorted(row_rows)
        if row[0] in roles_after
        and (row not in actual_rows or (row[0], row[1], row[2], row[4]) in delete_keys)
    ]

    # memberships (the admin account is never a candidate: its own memberships are implicit)
    managed_members = {
        m for g, m, *_ in actual.memberships if g == GW_MANAGED and m.startswith("u_")
    }
    user_rows = [
        row
        for row in sorted(actual.memberships)
        if row[0].startswith("g_") and row[1].startswith("u_") and row[1] != admin
    ]
    inheriting = {(g, m) for g, m, _, _, inherit, _ in user_rows if inherit}
    by_pair: dict[tuple[str, str], list[str]] = defaultdict(list)
    for group, member, grantor, *_ in user_rows:
        by_pair[(group, member)].append(grantor)
        if grantor != admin:
            reported.append(
                Drift(
                    "membership_grantor",
                    f"{member} is in {group} granted by {grantor}, not by {admin}",
                )
            )
    for pair, grantors in sorted(by_pair.items()):
        if pair not in members and all(g == admin for g in grantors):
            fixes.append(RevokeMembership(*pair))
    grant_members: list[PgOp] = [
        GrantMembership(g, m)
        for g, m in sorted(members - inheriting)
        if m != admin and g in roles_after and m in roles
    ]
    reported.extend(
        Drift("user_not_managed", f"{role} is not a member of {GW_MANAGED}")
        for role in sorted(
            r for r in roles if r.startswith("u_") and r != admin and r not in managed_members
        )
    )

    # grants after the revokes
    fixes.extend(grant_members)
    fixes.extend(GrantAllTablesSelect(s, r) for s, r in sorted(grant_all))
    fixes.extend(grant_tables)
    fixes.extend(grant_defaults)
    fixes.extend(upserts)

    # RLS
    for key in sorted(declared):
        enable = declared[key]
        if key not in row_security:
            reported.append(
                Drift(
                    "declared_table_missing",
                    f"{key[0]}.{key[1]} has a row_column tuple but no table",
                )
            )
            continue
        enabled, forced = row_security[key]
        healthy = (
            enabled
            and forced
            and policy_ok(
                policies.get((*key, "gw_passthrough")),
                "gw_passthrough",
                enable,
                column_type=column_types.get((*key, enable.column)),
            )
            and policy_ok(
                policies.get((*key, "gw_read")),
                "gw_read",
                enable,
                column_type=column_types.get((*key, enable.column)),
            )
            and (key[0], key[1], GW_MANAGED) in actual.table_select
        )
        if not healthy:
            fixes.append(enable)
        reported.extend(
            Drift(
                "extra_policy",
                f"{key[0]}.{key[1]} is row-controlled but also has policy {p.name!r}, "
                "which may widen access",
            )
            for p in sorted(actual.policies, key=lambda p: p.name)
            if (p.schema, p.table) == key and p.name not in _GW_POLICIES and p.permissive
        )
    for schema, table in sorted(policy_tables - set(declared)):
        reported.append(
            Drift(
                "undeclared_policy",
                f"{schema}.{table} has gw_* policies but no row_column tuple",
            )
        )

    # operator setup
    reported.extend(
        Drift("managed_usage_missing", f"{GW_MANAGED} lacks USAGE on schema {schema}")
        for schema in sorted(rule_schemas & schema_set)
        if (schema, GW_MANAGED) not in actual.schema_usage
    )
    return Plan(fixes, reported)


# --- Reconciler ---


async def _snapshot(
    conn: psycopg.AsyncConnection, owners: Sequence[str]
) -> tuple[str, list[str], dict[str, set[str]], ActualState]:
    cursor = await conn.execute(SQL("SELECT current_user"))
    row = await cursor.fetchone()
    assert row is not None
    admin = row[0]
    cursor = await conn.execute(
        SQL(
            "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname <> ALL({system}::text[]) "
            "AND left(nspname, 8) <> 'pg_toast' AND left(nspname, 7) <> 'pg_temp' "
            "ORDER BY nspname"
        ).format(system=Literal(list(_SYSTEM_SCHEMAS)))
    )
    schemas = [r[0] for r in await cursor.fetchall()]
    cursor = await conn.execute(
        SQL(
            "SELECT n.nspname, c.relname FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = ANY({}::text[]) AND c.relkind IN ('r', 'p', 'v', 'm', 'f')"
        ).format(Literal(schemas))
    )
    relations: dict[str, set[str]] = defaultdict(set)
    for schema, table in await cursor.fetchall():
        relations[schema].add(table)
    await conn.rollback()  # read_actual needs an idle connection
    state = await read_actual(conn, schemas=schemas, default_privilege_owners=owners)
    return admin, schemas, relations, state


def _describe(op: PgOp) -> dict[str, object]:
    return {"op": type(op).__name__, **asdict(op)}  # type: ignore[call-overload]


class Reconciler:
    def __init__(
        self,
        db: aiosqlite.Connection,
        store: PermissionStore,
        executor: Executor,
        connect: Callable[[str], Awaitable[psycopg.AsyncConnection]],
        locks: ConnectionLocks,
    ) -> None:
        self._db = db
        self._store = store
        self._executor = executor
        self._connect = connect
        self._locks = locks
        self._stop = asyncio.Event()

    async def _groups(self) -> list[str]:
        async with self._db.execute("SELECT name FROM groups ORDER BY name") as cur:
            return [row[0] for row in await cur.fetchall()]

    async def reconcile(self, connection: str, *, dry_run: bool = False) -> ReconcileReport:
        async with self._locks(connection):
            return await self._reconcile(connection, dry_run)

    async def reconcile_strict(self, connection: str) -> ReconcileReport:
        """``reconcile``, but raise ``ReconcileFailed`` when anything could not be applied."""
        report = await self.reconcile(connection)
        if report.error or report.failed:
            raise ReconcileFailed(report)
        return report

    async def _reconcile(self, connection: str, dry_run: bool) -> ReconcileReport:
        info = await load_connection(self._db, connection)
        ctx = mapping_context(await load_connections(self._db))
        tuples = await self._store.read()
        groups = await self._groups()
        ops, reported = expected_ops(tuples, ctx, connection)
        async with await self._connect(connection) as conn:
            admin, schemas, relations, state = await _snapshot(conn, info.default_privilege_owners)
        plan = diff(
            ops=ops,
            groups=groups,
            actual=state,
            relations=relations,
            schemas=schemas,
            admin=admin,
        )
        report = ReconcileReport(connection, dry_run, reported=[*reported, *plan.reported])
        if dry_run:
            report.fixes = list(plan.fixes)
            return report
        errors: list[str] = []
        for kind in _ORDER:
            batch = [op for op in plan.fixes if type(op) is kind]
            if not batch:
                continue
            try:
                skipped = await self._executor.apply(connection, batch)
            except Exception as exc:
                logger.warning("reconcile of %s failed on %s: %s", connection, kind.__name__, exc)
                errors.append(f"{kind.__name__}: {exc}")
                report.failed.extend(batch)
                continue
            report.skipped.extend(skipped)
            report.fixes.extend(op for op in batch if op not in skipped)
        if errors:
            report.error = "; ".join(errors)
        if report.fixes:
            await self._audit(info, report)
        return report

    async def _audit(self, info: ConnectionInfo, report: ReconcileReport) -> None:
        detail = {
            "source": "reconcile",
            "fixes": [_describe(op) for op in report.fixes],
            "reported": [asdict(d) for d in report.reported],
            "failed": [_describe(op) for op in report.failed],
            "error": report.error,
        }
        async with metadata.transaction(self._db):
            await audit.record(self._db, "sync", connection_id=info.id, detail=detail)

    async def reconcile_all(self, dry_run: bool = False) -> dict[str, ReconcileReport]:
        """Every registered connection; one failing connection does not stop the others."""
        results: dict[str, ReconcileReport] = {}
        for info in await load_connections(self._db):
            try:
                results[info.name] = await self.reconcile(info.name, dry_run=dry_run)
            except Exception as exc:
                logger.exception("reconcile of %s failed", info.name)
                results[info.name] = ReconcileReport(info.name, dry_run, error=str(exc))
        return results

    async def run_periodic(self, interval_s: float) -> None:
        """Reconcile everything once now, then every ``interval_s`` until ``stop()``."""
        while not self._stop.is_set():
            try:
                await self.reconcile_all()
            except Exception:
                logger.exception("periodic reconcile failed")
            try:
                await asyncio.wait_for(self._stop.wait(), interval_s)
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()
