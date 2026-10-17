"""Pure mapping from permission tuples to PostgreSQL operations."""

from db_gateway.permissions import ids
from db_gateway.permissions.store import Tuple
from db_gateway.permissions.types import (
    ALL,
    DeleteRowGrant,
    DisableRowPolicy,
    EnableRowPolicy,
    GrantAllTablesSelect,
    GrantDefaultSelect,
    GrantMembership,
    GrantTableSelect,
    MappingContext,
    PgOp,
    RevokeAllTablesSelect,
    RevokeDefaultSelect,
    RevokeMembership,
    RevokeTableSelect,
    TargetedOp,
    UpsertRowGrant,
    group_role,
    user_role,
)


def _group_userset(user: str) -> str:
    if not user.startswith("group:") or not user.endswith("#member"):
        raise ValueError(f"expected a group#member userset: {user}")
    return ids.parse_group(user)


def _check_connection(connection: str, ctx: MappingContext) -> None:
    if connection not in ctx.connections:
        raise ValueError(f"connection is not configured: {connection}")


def _inverse(op: PgOp) -> PgOp:
    match op:
        case GrantMembership(group=group, member=member):
            return RevokeMembership(group, member)
        case GrantAllTablesSelect(schema=schema, role=role):
            return RevokeAllTablesSelect(schema, role)
        case GrantDefaultSelect(owner=owner, schema=schema, role=role):
            return RevokeDefaultSelect(owner, schema, role)
        case GrantTableSelect(schema=schema, table=table, role=role):
            return RevokeTableSelect(schema, table, role)
        case UpsertRowGrant(group_role=role, schema=schema, table=table, value=value):
            return DeleteRowGrant(role, schema, table, value)
        case _:
            raise TypeError(f"no revoke operation for {type(op).__name__}")


def grant_ops(t: Tuple, ctx: MappingContext) -> list[TargetedOp]:
    """Return the fixed operations represented by one permission tuple."""
    object_type = t.object.partition(":")[0]

    if object_type == "group" and t.relation == "member":
        if t.object.endswith("#member"):
            raise ValueError(f"expected a group object: {t.object}")
        group_name = ids.parse_group(t.object)
        member = user_role(ids.parse_user(t.user))
        return [
            TargetedOp(connection, GrantMembership(group_role(group_name), member))
            for connection in ctx.connections
        ]

    if object_type == "db_schema" and t.relation == "reader":
        ref = ids.parse_db_schema(t.object)
        _check_connection(ref.connection, ctx)
        group_name = _group_userset(t.user)
        role = group_role(group_name)
        grants: list[TargetedOp] = [
            TargetedOp(ref.connection, GrantAllTablesSelect(ref.schema, role))
        ]
        grants.extend(
            TargetedOp(ref.connection, GrantDefaultSelect(owner, ref.schema, role))
            for owner in ctx.default_privilege_owners.get(ref.connection, ())
        )
        grants.append(TargetedOp(ref.connection, UpsertRowGrant(role, ref.schema, ALL, ALL, ALL)))
        return grants

    if object_type == "db_table" and t.relation == "reader":
        ref = ids.parse_db_table(t.object)
        _check_connection(ref.connection, ctx)
        if ref.table == ALL:
            raise ValueError("'*' is not a legal table name")
        role = group_role(_group_userset(t.user))
        return [
            TargetedOp(ref.connection, GrantTableSelect(ref.schema, ref.table, role)),
            TargetedOp(
                ref.connection,
                UpsertRowGrant(role, ref.schema, ref.table, ALL, ALL),
            ),
        ]

    if object_type == "row_set":
        ref = ids.parse_row_set(t.object)
        _check_connection(ref.connection, ctx)
        if ref.table == ALL:
            raise ValueError("'*' is not a legal table name")
        if ref.column == ALL:
            raise ValueError("'*' is not a legal column name")
        if ref.value == ALL:
            raise ValueError("'*' is not a legal row value")
        if t.relation == "table":
            if not t.user.startswith("db_table:"):
                raise ValueError(f"expected a db_table object: {t.user}")
            table_ref = ids.parse_db_table(t.user)
            _check_connection(table_ref.connection, ctx)
            if table_ref.table == ALL:
                raise ValueError("'*' is not a legal table name")
            return []
        if t.relation == "reader":
            parent_table = ctx.row_set_tables.get(t.object)
            if parent_table is not None:
                table_ref = ids.parse_db_table(parent_table)
                if (table_ref.connection, table_ref.schema, table_ref.table) != (
                    ref.connection,
                    ref.schema,
                    ref.table,
                ):
                    raise ValueError(f"row_set table does not match its id: {t.object}")
            role = group_role(_group_userset(t.user))
            return [
                TargetedOp(
                    ref.connection,
                    UpsertRowGrant(role, ref.schema, ref.table, ref.column, ref.value),
                )
            ]
        raise ValueError(f"unsupported row_set relation: {t.relation}")

    if t.object == ids.GATEWAY_MAIN and object_type == "gateway" and t.relation == "admin":
        ids.parse_user(t.user)
        return []

    raise ValueError(f"unsupported permission tuple: {t!r}")


def revoke_ops(t: Tuple, ctx: MappingContext) -> list[TargetedOp]:
    """Return the inverse operations in reverse grant order."""
    grants = grant_ops(t, ctx)
    return [TargetedOp(target.connection, _inverse(target.op)) for target in reversed(grants)]


def row_policy_enable_ops(
    connection: str, schema: str, table: str, column: str
) -> list[TargetedOp]:
    """Return the operation that enables row-level filtering for a table."""
    return [TargetedOp(connection, EnableRowPolicy(schema, table, column))]


def row_policy_disable_ops(connection: str, schema: str, table: str) -> list[TargetedOp]:
    """Return the operation that disables row-level filtering for a table."""
    return [TargetedOp(connection, DisableRowPolicy(schema, table))]
