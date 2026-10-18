"""Render PostgreSQL permission operations as safely composed SQL."""

from dataclasses import dataclass

from psycopg import sql
from psycopg.sql import Composable

from db_gateway.permissions import types
from db_gateway.permissions.types import (
    CreateGroupRole,
    DeleteRowGrant,
    DisableRowPolicy,
    DropGroupRole,
    EnableRowPolicy,
    GrantAllTablesSelect,
    GrantDefaultSelect,
    GrantMembership,
    GrantSchemaUsage,
    GrantTableSelect,
    PgOp,
    RevokeAllTablesSelect,
    RevokeDefaultSelect,
    RevokeMembership,
    RevokeTableSelect,
    UpsertRowGrant,
)

_ROW_GRANTS = sql.Identifier("gateway_acl", "row_grants")


@dataclass(frozen=True, slots=True)
class RequiredObjects:
    """Database objects that must exist before a replayed operation runs."""

    roles: tuple[str, ...] = ()
    schemas: tuple[str, ...] = ()
    tables: tuple[tuple[str, str], ...] = ()


def _table(schema: str, table: str) -> sql.Identifier:
    return sql.Identifier(schema, table)


def _row_grant_values(*values: str) -> Composable:
    return sql.SQL(", ").join(sql.Literal(value) for value in values)


def render(op: PgOp) -> list[Composable]:
    """Render a PostgreSQL operation into one or more SQL statements."""
    match op:
        case CreateGroupRole(role=role):
            statement = sql.SQL(
                "DO $gw$ BEGIN "
                "IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {role}) "
                "THEN EXECUTE format('CREATE ROLE %I NOLOGIN', {role}); "
                "END IF; END $gw$"
            ).format(role=sql.Literal(role))
            return [statement]
        case DropGroupRole(role=role):
            return [
                sql.SQL("DELETE FROM {} WHERE {} = {}").format(
                    _ROW_GRANTS, sql.Identifier("group_role"), sql.Literal(role)
                ),
                sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)),
            ]
        case GrantMembership(group=group, member=member):
            # Explicit INHERIT TRUE: re-granting also repairs a membership whose
            # inherit option was turned off (PG16+ keeps per-grant options).
            return [
                sql.SQL("GRANT {} TO {} WITH INHERIT TRUE").format(
                    sql.Identifier(group), sql.Identifier(member)
                )
            ]
        case RevokeMembership(group=group, member=member):
            return [
                sql.SQL("REVOKE {} FROM {}").format(sql.Identifier(group), sql.Identifier(member))
            ]
        case GrantSchemaUsage(schema=schema, role=role):
            return [
                sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(schema), sql.Identifier(role)
                )
            ]
        case GrantTableSelect(schema=schema, table=table, role=role):
            return [
                sql.SQL("GRANT SELECT ON TABLE {} TO {}").format(
                    _table(schema, table), sql.Identifier(role)
                )
            ]
        case RevokeTableSelect(schema=schema, table=table, role=role):
            return [
                sql.SQL("REVOKE SELECT ON TABLE {} FROM {}").format(
                    _table(schema, table), sql.Identifier(role)
                )
            ]
        case GrantAllTablesSelect(schema=schema, role=role):
            return [
                sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}").format(
                    sql.Identifier(schema), sql.Identifier(role)
                )
            ]
        case RevokeAllTablesSelect(schema=schema, role=role):
            return [
                sql.SQL("REVOKE SELECT ON ALL TABLES IN SCHEMA {} FROM {}").format(
                    sql.Identifier(schema), sql.Identifier(role)
                )
            ]
        case GrantDefaultSelect(owner=owner, schema=schema, role=role):
            return [
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} GRANT SELECT ON TABLES TO {}"
                ).format(sql.Identifier(owner), sql.Identifier(schema), sql.Identifier(role))
            ]
        case RevokeDefaultSelect(owner=owner, schema=schema, role=role):
            return [
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} REVOKE "
                    "SELECT ON TABLES FROM {}"
                ).format(sql.Identifier(owner), sql.Identifier(schema), sql.Identifier(role))
            ]
        case UpsertRowGrant(
            group_role=role, schema=schema, table=table, column=column, value=value
        ):
            columns = sql.SQL(", ").join(
                sql.Identifier(name)
                for name in (
                    "group_role",
                    "schema_name",
                    "table_name",
                    "column_name",
                    "value",
                )
            )
            return [
                sql.SQL("INSERT INTO {} ({}) VALUES ({}) ON CONFLICT DO NOTHING").format(
                    _ROW_GRANTS,
                    columns,
                    _row_grant_values(role, schema, table, column, value),
                )
            ]
        case DeleteRowGrant(group_role=role, schema=schema, table=table, value=value):
            conditions = sql.SQL(" AND ").join(
                sql.SQL("{} = {}").format(sql.Identifier(column), sql.Literal(item))
                for column, item in (
                    ("group_role", role),
                    ("schema_name", schema),
                    ("table_name", table),
                    ("value", value),
                )
            )
            return [sql.SQL("DELETE FROM {} WHERE {}").format(_ROW_GRANTS, conditions)]
        case EnableRowPolicy(schema=schema, table=table, column=column):
            qualified_table = _table(schema, table)
            policy_passthrough = sql.Identifier("gw_passthrough")
            policy_read = sql.Identifier("gw_read")
            return [
                sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(qualified_table),
                sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(qualified_table),
                sql.SQL("DROP POLICY IF EXISTS {} ON {}").format(
                    policy_passthrough, qualified_table
                ),
                sql.SQL("CREATE POLICY {} ON {} USING (NOT (SELECT {}()))").format(
                    policy_passthrough,
                    qualified_table,
                    sql.Identifier("gateway_acl", "is_managed"),
                ),
                sql.SQL("DROP POLICY IF EXISTS {} ON {}").format(policy_read, qualified_table),
                sql.SQL(
                    "CREATE POLICY {} ON {} FOR SELECT USING "
                    "((SELECT {}({}, {})) OR {}::text = ANY "
                    "((SELECT {}({}, {}))::text[]))"
                ).format(
                    policy_read,
                    qualified_table,
                    sql.Identifier("gateway_acl", "allow_all"),
                    sql.Literal(schema),
                    sql.Literal(table),
                    sql.Identifier(column),
                    sql.Identifier("gateway_acl", "allowed_values"),
                    sql.Literal(schema),
                    sql.Literal(table),
                ),
                sql.SQL("GRANT SELECT ON TABLE {} TO {}").format(
                    qualified_table, sql.Identifier(types.GW_MANAGED)
                ),
            ]
        case DisableRowPolicy(schema=schema, table=table):
            qualified_table = _table(schema, table)
            return [
                sql.SQL("DROP POLICY IF EXISTS {} ON {}").format(
                    sql.Identifier("gw_passthrough"), qualified_table
                ),
                sql.SQL("DROP POLICY IF EXISTS {} ON {}").format(
                    sql.Identifier("gw_read"), qualified_table
                ),
                sql.SQL("ALTER TABLE {} NO FORCE ROW LEVEL SECURITY").format(qualified_table),
                sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY").format(qualified_table),
                sql.SQL("REVOKE SELECT ON TABLE {} FROM {}").format(
                    qualified_table, sql.Identifier(types.GW_MANAGED)
                ),
            ]
        case _:
            raise TypeError(f"unsupported PostgreSQL operation: {type(op).__name__}")


def required_roles(op: PgOp) -> tuple[str, ...]:
    """Return the roles that must exist before applying a membership operation."""
    match op:
        case GrantMembership(group=group, member=member):
            return (group, member)
        case RevokeMembership(group=group, member=member):
            return (group, member)
        case _:
            return ()


def required_objects(op: PgOp) -> RequiredObjects:
    """Describe roles and SQL objects that replay validation must find."""
    match op:
        case CreateGroupRole() | DropGroupRole():
            return RequiredObjects()
        case (
            GrantMembership(group=group, member=member)
            | RevokeMembership(group=group, member=member)
        ):
            return RequiredObjects(roles=(group, member))
        case GrantSchemaUsage(schema=schema, role=role):
            return RequiredObjects(roles=(role,), schemas=(schema,))
        case (
            GrantTableSelect(schema=schema, table=table, role=role)
            | RevokeTableSelect(schema=schema, table=table, role=role)
        ):
            return RequiredObjects(roles=(role,), schemas=(schema,), tables=((schema, table),))
        case (
            GrantAllTablesSelect(schema=schema, role=role)
            | RevokeAllTablesSelect(schema=schema, role=role)
        ):
            return RequiredObjects(roles=(role,), schemas=(schema,))
        case (
            GrantDefaultSelect(owner=owner, schema=schema, role=role)
            | RevokeDefaultSelect(owner=owner, schema=schema, role=role)
        ):
            return RequiredObjects(roles=(owner, role), schemas=(schema,))
        case UpsertRowGrant(group_role=role):
            return RequiredObjects(roles=(role,))
        case DeleteRowGrant():
            return RequiredObjects()  # never skipped (types.py)
        case (
            EnableRowPolicy(schema=schema, table=table)
            | DisableRowPolicy(schema=schema, table=table)
        ):
            return RequiredObjects(
                roles=(types.GW_MANAGED,), schemas=(schema,), tables=((schema, table),)
            )
        case _:
            raise TypeError(f"unsupported PostgreSQL operation: {type(op).__name__}")
