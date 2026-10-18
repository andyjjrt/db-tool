"""Find objects through which a gateway user can read rows the policies would hide.

Read-only catalog scans, run with search_path pinned to pg_catalog like
``actual.py``.

Exposure model (plan §2.5). The gateway's policies are not role-scoped:
``gw_passthrough`` / ``gw_read`` decide with ``session_user`` and every
controlled table has FORCE ROW LEVEL SECURITY. PostgreSQL checks a view's base
relations as the view owner (normal view) or as the querying user
(``security_invoker`` view; this holds even when the invoker view is reached
through a normal view). So:

- A normal view whose owner has neither ``rolsuper`` nor ``rolbypassrls`` does
  not leak: RLS still applies and the policies see the gateway user's own
  ``session_user``. It is not reported.
- A normal view (``security_invoker`` unset or false in any boolean spelling)
  owned by a ``rolsuper`` / ``rolbypassrls`` role that directly reads a
  controlled table leaks: RLS is skipped for its owner (reason
  ``bypass_owner``).
- A materialized view whose query reaches a controlled table through any path
  leaks: its contents were computed at REFRESH time, possibly by an admin
  session that sees everything (reason ``matview``).
- A materialized view whose query calls a function outside system schemas and
  extensions leaks too, whatever the function is (definer or invoker): the
  function ran at REFRESH time under the refreshing session (reason
  ``matview``; ``reads`` may be empty).
- RLS is applied per relation named in the query, so a partition-family
  member (ancestor or descendant, see below) that is not itself in the input
  is an unprotected entry point. A normal view, owned by anyone, that
  directly reads such a member leaks (reason ``unprotected_partition``;
  ``reads`` names the controlled table). Invoker views reading it do not: the
  querying user would need SELECT on that member itself.
- A view of any ``security_invoker`` value whose query calls a SECURITY
  DEFINER function owned by a ``rolsuper`` / ``rolbypassrls`` role leaks,
  whatever the function reads (reason ``bypass_definer_function``; ``reads``
  may be empty). Bodies are not analysed, and only functions recorded as
  dependencies of the view's ``_RETURN`` rule (called in the view query) are
  seen; functions reached indirectly through other functions are not.
- Any view or matview, of any ``security_invoker`` value, from which some
  dependency path reaches such a leaking point (itself included) is reported.
  Traversal continues through an intermediate relation only when it leads to a
  leaking point, so an owner-run view over an invoker view over the table is
  not reported. ``reads`` is the controlled tables reached through leaking
  points. ``reason`` is the first of ``matview``, ``bypass_owner``,
  ``bypass_definer_function``, ``unprotected_partition`` among the reasons of
  the leaking points reached.
- Foreign tables are not analysed: a ``postgres_fdw`` alias to a controlled
  table (a loopback connection under a mapped user) has no local dependency on
  it. Creating a foreign server and user mapping is DB-owner / superuser
  configuration, which the plan (§11) treats as outside the gateway's
  protection.

Partitions (``pg_inherits``): a controlled table stands for its whole
partition tree on the way down and its ancestors on the way up, i.e. a view
on the parent of a controlled partition, on a partition of a controlled
parent, or on any sub-partition counts, and ``reads`` names the controlled
table from the input. Siblings of a controlled partition do not count.

Functions: every SECURITY DEFINER function outside system schemas and
extensions, with whether its owner bypasses RLS (``rolsuper`` /
``rolbypassrls``). Bodies are not analysed; this is report-only data.
"""

from collections.abc import Collection
from dataclasses import dataclass
from typing import Literal as LiteralType

import psycopg
from psycopg.sql import SQL
from psycopg.sql import Literal as SqlLiteral

_PIN_SEARCH_PATH = SQL("SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)")

_SYSTEM_SCHEMAS = ("pg_catalog", "information_schema", "gateway_acl", "paradedb")
_INVOKER = (
    "EXISTS (SELECT 1 FROM unnest(c.reloptions) opt "
    "WHERE lower(opt) ~ '^security_invoker=(t|tr|tru|true|y|ye|yes|on|1)$')"
)
_REASON_ORDER = ("matview", "bypass_owner", "bypass_definer_function", "unprotected_partition")
_NOT_SYSTEM = SQL(
    "n.nspname <> ALL({system}::text[]) "
    "AND left(n.nspname, 8) <> 'pg_toast' AND left(n.nspname, 7) <> 'pg_temp'"
).format(system=SqlLiteral(list(_SYSTEM_SCHEMAS)))


@dataclass(frozen=True, slots=True)
class UnsafeView:
    schema: str
    name: str
    kind: LiteralType["view", "matview"]
    owner: str
    reads: tuple[tuple[str, str], ...]
    reason: LiteralType[
        "matview", "bypass_owner", "bypass_definer_function", "unprotected_partition"
    ]


@dataclass(frozen=True, slots=True)
class DefinerFunction:
    schema: str
    name: str
    identity_args: str
    owner: str
    executable_by_managed: bool
    owner_bypasses_rls: bool


async def unsafe_views(
    conn: psycopg.AsyncConnection, tables: Collection[tuple[str, str]]
) -> list[UnsafeView]:
    ordered = sorted(set(tables))
    if not ordered:
        return []
    async with conn.transaction():
        await conn.execute(_PIN_SEARCH_PATH)
        cursor = await conn.execute(
            SQL(
                "WITH RECURSIVE "
                "ctl AS (SELECT t.s, t.t, c.oid FROM unnest({schemas}::text[], {names}::text[]) "
                "AS t(s, t) JOIN pg_catalog.pg_namespace n ON n.nspname = t.s "
                "JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = t.t), "
                "fam(s, t, oid) AS (SELECT s, t, oid FROM ctl "
                "UNION SELECT fam.s, fam.t, i.inhrelid FROM fam "
                "JOIN pg_catalog.pg_inherits i ON i.inhparent = fam.oid), "
                "up(s, t, oid) AS (SELECT s, t, oid FROM ctl "
                "UNION SELECT up.s, up.t, i.inhparent FROM up "
                "JOIN pg_catalog.pg_inherits i ON i.inhrelid = up.oid), "
                "allrel AS (SELECT s, t, oid FROM fam UNION SELECT s, t, oid FROM up), "
                "edge(v, r) AS (SELECT DISTINCT rw.ev_class, d.refobjid "
                "FROM pg_catalog.pg_rewrite rw JOIN pg_catalog.pg_depend d "
                "ON d.classid = 'pg_catalog.pg_rewrite'::regclass AND d.objid = rw.oid "
                "AND d.refclassid = 'pg_catalog.pg_class'::regclass "
                "WHERE rw.rulename = '_RETURN' AND d.refobjid <> rw.ev_class), "
                "reach(s, t, v) AS (SELECT a.s, a.t, e.v FROM allrel a "
                "JOIN edge e ON e.r = a.oid "
                "UNION SELECT reach.s, reach.t, e.v FROM reach "
                "JOIN edge e ON e.r = reach.v), "
                "leak(s, t, v, k) AS ("
                "SELECT r.s, r.t, r.v, 'matview' FROM reach r "
                "JOIN pg_catalog.pg_class c ON c.oid = r.v WHERE c.relkind = 'm' "
                "UNION ALL SELECT r.s, r.t, r.v, 'bypass_owner' FROM reach r "
                "JOIN pg_catalog.pg_class c ON c.oid = r.v "
                "JOIN pg_catalog.pg_roles o ON o.oid = c.relowner "
                "WHERE c.relkind = 'v' AND NOT {invoker} AND (o.rolsuper OR o.rolbypassrls) "
                "AND EXISTS (SELECT 1 FROM edge e JOIN allrel a ON a.oid = e.r "
                "WHERE e.v = r.v AND a.s = r.s AND a.t = r.t) "
                "UNION ALL SELECT r.s, r.t, r.v, 'unprotected_partition' FROM reach r "
                "JOIN pg_catalog.pg_class c ON c.oid = r.v "
                "WHERE c.relkind = 'v' AND NOT {invoker} AND EXISTS (SELECT 1 FROM edge e "
                "JOIN allrel a ON a.oid = e.r WHERE e.v = r.v AND a.s = r.s AND a.t = r.t "
                "AND a.oid NOT IN (SELECT oid FROM ctl)) "
                "UNION ALL SELECT NULL::text, NULL::text, rw.ev_class, 'bypass_definer_function' "
                "FROM pg_catalog.pg_rewrite rw "
                "JOIN pg_catalog.pg_class c ON c.oid = rw.ev_class AND c.relkind = 'v' "
                "JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_rewrite'::regclass "
                "AND d.objid = rw.oid AND d.refclassid = 'pg_catalog.pg_proc'::regclass "
                "JOIN pg_catalog.pg_proc p ON p.oid = d.refobjid AND p.prosecdef "
                "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                "JOIN pg_catalog.pg_roles o ON o.oid = p.proowner "
                "WHERE rw.rulename = '_RETURN' AND (o.rolsuper OR o.rolbypassrls) "
                "AND {not_system} "
                "UNION ALL SELECT NULL::text, NULL::text, rw.ev_class, 'matview' "
                "FROM pg_catalog.pg_rewrite rw "
                "JOIN pg_catalog.pg_class c ON c.oid = rw.ev_class AND c.relkind = 'm' "
                "JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_rewrite'::regclass "
                "AND d.objid = rw.oid AND d.refclassid = 'pg_catalog.pg_proc'::regclass "
                "JOIN pg_catalog.pg_proc p ON p.oid = d.refobjid "
                "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                "WHERE rw.rulename = '_RETURN' AND {not_system} "
                "AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend x "
                "WHERE x.classid = 'pg_catalog.pg_proc'::regclass AND x.objid = p.oid "
                "AND x.deptype = 'e')), "
                "expose(s, t, v, k) AS (SELECT s, t, v, k FROM leak "
                "UNION SELECT x.s, x.t, e.v, x.k FROM expose x JOIN edge e ON e.r = x.v) "
                "SELECT n.nspname, c.relname, c.relkind, o.rolname, x.s, x.t, x.k "
                "FROM expose x JOIN pg_catalog.pg_class c ON c.oid = x.v "
                "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "JOIN pg_catalog.pg_roles o ON o.oid = c.relowner "
                "WHERE c.relkind IN ('v', 'm') AND {not_system}"
            ).format(
                schemas=SqlLiteral([s for s, _ in ordered]),
                names=SqlLiteral([t for _, t in ordered]),
                invoker=SQL(_INVOKER),
                not_system=_NOT_SYSTEM,
            )
        )
        rows = await cursor.fetchall()
    found: dict[tuple[str, str, str, str], tuple[set[tuple[str, str]], set[str]]] = {}
    for schema, name, relkind, owner, table_schema, table_name, reason in rows:
        kind = "matview" if relkind == "m" else "view"
        reads, reasons = found.setdefault((schema, name, kind, owner), (set(), set()))
        if table_schema is not None:
            reads.add((table_schema, table_name))
        reasons.add(reason)
    return [
        UnsafeView(
            schema,
            name,
            kind,  # pyright: ignore[reportArgumentType]
            owner,
            tuple(sorted(reads)),
            min(reasons, key=_REASON_ORDER.index),  # pyright: ignore[reportArgumentType]
        )
        for (schema, name, kind, owner), (reads, reasons) in sorted(found.items())
    ]


async def definer_functions(conn: psycopg.AsyncConnection) -> list[DefinerFunction]:
    async with conn.transaction():
        await conn.execute(_PIN_SEARCH_PATH)
        cursor = await conn.execute(
            SQL(
                "SELECT n.nspname, p.proname, "
                "pg_catalog.pg_get_function_identity_arguments(p.oid), "
                "o.rolname, CASE WHEN EXISTS (SELECT 1 FROM pg_catalog.pg_roles "
                "WHERE rolname = 'gw_managed') "
                "THEN pg_catalog.has_function_privilege('gw_managed', p.oid, 'EXECUTE') "
                "ELSE p.proacl IS NULL OR EXISTS (SELECT 1 FROM "
                "pg_catalog.aclexplode(p.proacl) a "
                "WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') END, "
                "o.rolsuper OR o.rolbypassrls "
                "FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                "JOIN pg_catalog.pg_roles o ON o.oid = p.proowner "
                "WHERE p.prosecdef AND {not_system} AND NOT EXISTS (SELECT 1 "
                "FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_proc'::regclass "
                "AND d.objid = p.oid AND d.deptype = 'e') "
                "ORDER BY 1, 2, 3"
            ).format(not_system=_NOT_SYSTEM)
        )
        rows = await cursor.fetchall()
    return [DefinerFunction(*row) for row in rows]
