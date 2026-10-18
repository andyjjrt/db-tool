"""Read explicit gateway permission state as the target database's admin.

ACL readers report direct SELECT/USAGE grants, not effective or inherited
privileges, for grantees named g_*, u_*, or gw_managed. Owner and PUBLIC grants
are excluded. Table and schema ACLs are scoped to the supplied schemas;
table default ACLs are additionally scoped to the supplied owner roles.
Memberships include every grantor row whose member is a gateway grantee,
including unexpected parent roles, with ADMIN/INHERIT/SET flags. Roles lists
only existing g_* and u_* roles (cluster-wide).

RLS readers include flags for every ordinary/partitioned table in the supplied
schemas, and definitions of the two gateway policies, including their targets.
Row grants include ALL gateway_acl.row_grants rows, even orphans and rows outside
the supplied schemas, so the Reconciler can detect and delete stale entries.
All returned records are immutable and contain names rather than catalog OIDs.
"""

from collections.abc import Sequence
from dataclasses import dataclass

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.sql import SQL, Literal

# All ACL queries use r as the grantee alias. The underscore is literal, not
# the single-character wildcard in LIKE 'g_%'.
_MANAGED_GRANTEE = SQL("(left(r.rolname, 2) IN ('g_', 'u_') OR r.rolname = 'gw_managed')")

TableSelect = tuple[str, str, str]  # schema, table, grantee
SchemaUsage = tuple[str, str]  # schema, grantee
DefaultSelect = tuple[str, str, str]  # owner, schema, grantee
Membership = tuple[str, str, str, bool, bool, bool]  # group, member, grantor, admin, inherit, set
RowSecurity = tuple[str, str, bool, bool]  # schema, table, enabled, forced
RowGrant = tuple[str, str, str, str, str]  # group, schema, table, column, value


@dataclass(frozen=True, slots=True)
class RowPolicy:
    schema: str
    table: str
    name: str
    command: str
    permissive: bool
    roles: tuple[str, ...]
    using: str | None
    with_check: str | None


@dataclass(frozen=True, slots=True)
class ActualState:
    table_select: frozenset[TableSelect]
    schema_usage: frozenset[SchemaUsage]
    default_select: frozenset[DefaultSelect]
    memberships: frozenset[Membership]
    roles: frozenset[str]
    row_security: frozenset[RowSecurity]
    policies: frozenset[RowPolicy]
    row_grants: frozenset[RowGrant]


async def read_table_select(
    conn: psycopg.AsyncConnection, schemas: Sequence[str]
) -> frozenset[TableSelect]:
    cursor = await conn.execute(
        SQL(
            "SELECT n.nspname, c.relname, r.rolname "
            "FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a "
            "JOIN pg_catalog.pg_roles r ON r.oid = a.grantee "
            "WHERE n.nspname = ANY({schemas}::text[]) "
            "AND c.relkind IN ('r', 'p', 'v', 'm', 'f') "
            "AND a.privilege_type = 'SELECT' AND a.grantee <> c.relowner AND {managed}"
        ).format(schemas=Literal(list(schemas)), managed=_MANAGED_GRANTEE)
    )
    return frozenset(await cursor.fetchall())


async def read_schema_usage(
    conn: psycopg.AsyncConnection, schemas: Sequence[str]
) -> frozenset[SchemaUsage]:
    cursor = await conn.execute(
        SQL(
            "SELECT n.nspname, r.rolname FROM pg_catalog.pg_namespace n "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) a "
            "JOIN pg_catalog.pg_roles r ON r.oid = a.grantee "
            "WHERE n.nspname = ANY({schemas}::text[]) "
            "AND a.privilege_type = 'USAGE' AND a.grantee <> n.nspowner AND {managed}"
        ).format(schemas=Literal(list(schemas)), managed=_MANAGED_GRANTEE)
    )
    return frozenset(await cursor.fetchall())


async def read_default_select(
    conn: psycopg.AsyncConnection,
    schemas: Sequence[str],
    owners: Sequence[str],
) -> frozenset[DefaultSelect]:
    cursor = await conn.execute(
        SQL(
            "SELECT owner.rolname, n.nspname, r.rolname FROM pg_catalog.pg_default_acl d "
            "JOIN pg_catalog.pg_roles owner ON owner.oid = d.defaclrole "
            "JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a "
            "JOIN pg_catalog.pg_roles r ON r.oid = a.grantee "
            "WHERE d.defaclobjtype = 'r' AND n.nspname = ANY({schemas}::text[]) "
            "AND owner.rolname = ANY({owners}::text[]) "
            "AND a.privilege_type = 'SELECT' AND a.grantee <> d.defaclrole AND {managed}"
        ).format(
            schemas=Literal(list(schemas)),
            owners=Literal(list(owners)),
            managed=_MANAGED_GRANTEE,
        )
    )
    return frozenset(await cursor.fetchall())


async def read_memberships(conn: psycopg.AsyncConnection) -> frozenset[Membership]:
    cursor = await conn.execute(
        SQL(
            "SELECT g.rolname, r.rolname, grantor.rolname, "
            "m.admin_option, m.inherit_option, m.set_option "
            "FROM pg_catalog.pg_auth_members m "
            "JOIN pg_catalog.pg_roles g ON g.oid = m.roleid "
            "JOIN pg_catalog.pg_roles r ON r.oid = m.member "
            "JOIN pg_catalog.pg_roles grantor ON grantor.oid = m.grantor WHERE {managed}"
        ).format(managed=_MANAGED_GRANTEE)
    )
    return frozenset(await cursor.fetchall())


async def read_roles(conn: psycopg.AsyncConnection) -> frozenset[str]:
    cursor = await conn.execute(
        SQL("SELECT rolname FROM pg_catalog.pg_roles WHERE left(rolname, 2) IN ('g_', 'u_')")
    )
    return frozenset(row[0] for row in await cursor.fetchall())


async def read_row_security(
    conn: psycopg.AsyncConnection, schemas: Sequence[str]
) -> frozenset[RowSecurity]:
    cursor = await conn.execute(
        SQL(
            "SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity "
            "FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = ANY({}::text[]) AND c.relkind IN ('r', 'p')"
        ).format(Literal(list(schemas)))
    )
    return frozenset(await cursor.fetchall())


async def read_policies(
    conn: psycopg.AsyncConnection, schemas: Sequence[str]
) -> frozenset[RowPolicy]:
    cursor = await conn.execute(
        SQL(
            "SELECT n.nspname, c.relname, p.polname, p.polcmd, p.polpermissive, "
            "ARRAY(SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC' ELSE r.rolname END "
            "FROM unnest(p.polroles) role_oid "
            "LEFT JOIN pg_catalog.pg_roles r ON r.oid = role_oid ORDER BY 1), "
            "pg_catalog.pg_get_expr(p.polqual, p.polrelid), "
            "pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) "
            "FROM pg_catalog.pg_policy p "
            "JOIN pg_catalog.pg_class c ON c.oid = p.polrelid "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = ANY({}::text[]) "
            "AND p.polname IN ('gw_passthrough', 'gw_read')"
        ).format(Literal(list(schemas)))
    )
    rows = await cursor.fetchall()
    return frozenset(
        RowPolicy(schema, table, name, command, permissive, tuple(roles), using, with_check)
        for schema, table, name, command, permissive, roles, using, with_check in rows
    )


async def read_row_grants(conn: psycopg.AsyncConnection) -> frozenset[RowGrant]:
    cursor = await conn.execute(
        SQL(
            "SELECT group_role, schema_name, table_name, column_name, value "
            "FROM gateway_acl.row_grants"
        )
    )
    return frozenset(await cursor.fetchall())


async def read_actual(
    conn: psycopg.AsyncConnection,
    *,
    schemas: Sequence[str],
    default_privilege_owners: Sequence[str] = (),
) -> ActualState:
    """Read a consistent snapshot in a READ ONLY, REPEATABLE READ transaction.

    Requires an idle admin connection; ownership and closing remain with the
    caller. Individual readers may instead be used inside a caller's transaction.
    """
    if conn.info.transaction_status is not TransactionStatus.IDLE:
        raise ValueError("read_actual requires an idle connection")
    async with conn.transaction():
        await conn.execute(SQL("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        return ActualState(
            table_select=await read_table_select(conn, schemas),
            schema_usage=await read_schema_usage(conn, schemas),
            default_select=await read_default_select(conn, schemas, default_privilege_owners),
            memberships=await read_memberships(conn),
            roles=await read_roles(conn),
            row_security=await read_row_security(conn, schemas),
            policies=await read_policies(conn, schemas),
            row_grants=await read_row_grants(conn),
        )
