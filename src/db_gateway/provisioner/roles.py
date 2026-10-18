"""Personal roles (``u_<id>``) and their ``g_*`` memberships.

The plan gives the personal role two duties: it must inherit ``gw_managed`` so
that the RLS functions recognise it as a managed user, and it must be a member
of the group roles OpenFGA grants it. This module is the smallest provisioner
that provides both; M1 owns credentials and sessions.

The admin connection is passed in by the caller everywhere: this code never
opens, pools or commits a connection of its own, and every statement is built
with ``psycopg.sql``.
"""

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.sql import SQL, Identifier, Literal

from db_gateway.permissions import ids
from db_gateway.permissions.context import ConnectionLocks
from db_gateway.permissions.executor_protocol import Executor
from db_gateway.permissions.store import PermissionStore
from db_gateway.permissions.types import (
    GW_MANAGED,
    GrantMembership,
    RevokeMembership,
    group_role,
    user_role,
)

# Create the role if it is missing, and give an existing NOINHERIT role the
# INHERIT attribute back. The LOGIN attribute is never forced: NOINHERIT is the
# only attribute that would break the permission model (docs/target-db-setup.md),
# and M1 owns the rest of the role's attributes.
_CREATE_OR_FIX_ROLE = SQL(
    "DO $provisioner$ BEGIN "
    "IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {role}) THEN "
    "EXECUTE format('CREATE ROLE %I LOGIN INHERIT', {role}); "
    "ELSIF NOT EXISTS ("
    "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {role} AND rolinherit) THEN "
    "EXECUTE format('ALTER ROLE %I INHERIT', {role}); "
    "END IF; END $provisioner$"
)

# The g_* roles the member currently belongs to; g_ is literal, not a wildcard.
_MEMBERSHIPS_OF = SQL(
    "SELECT g.rolname, m.inherit_option, grantor.rolname "
    "FROM pg_catalog.pg_auth_members m "
    "JOIN pg_catalog.pg_roles grantor ON grantor.oid = m.grantor "
    "JOIN pg_catalog.pg_roles g ON g.oid = m.roleid "
    "JOIN pg_catalog.pg_roles u ON u.oid = m.member "
    "WHERE u.rolname = {} AND left(g.rolname, 2) = 'g_'"
)


async def ensure_user_role(conn: psycopg.AsyncConnection, user_id: int) -> None:
    """Create ``u_<user_id>`` and make it inherit ``gw_managed``.

    Idempotent. All statements run in one transaction with
    ``createrole_self_grant`` cleared, so the admin account never gains a
    membership in the role it creates (``check_target_db`` reports such a
    setting as ``admin_is_managed``). ``conn`` must be an idle admin
    connection; the caller owns it.
    """
    role = user_role(user_id)
    if role == conn.info.user:
        raise ValueError(f"refusing to alter the admin account itself: {role!r}")
    if conn.info.transaction_status is not TransactionStatus.IDLE:
        raise ValueError("ensure_user_role requires an idle connection")
    async with conn.transaction():
        await conn.execute(SQL("SET LOCAL createrole_self_grant = ''"))
        await conn.execute(_CREATE_OR_FIX_ROLE.format(role=Literal(role)))
        # Re-granting updates the options of an existing membership, if any.
        await conn.execute(
            SQL("GRANT {} TO {} WITH INHERIT TRUE").format(Identifier(GW_MANAGED), Identifier(role))
        )


async def _sync_memberships(
    conn: psycopg.AsyncConnection,
    store: PermissionStore,
    executor: Executor,
    connection: str,
    user_id: int,
) -> None:
    """Reconcile memberships; the caller owns ``conn`` and holds the lock."""
    role = user_role(user_id)
    if role == conn.info.user:
        raise ValueError(f"refusing to alter the admin account itself: {role!r}")
    if conn.info.transaction_status is not TransactionStatus.IDLE:
        raise ValueError("sync_user_memberships requires an idle connection")
    members = await store.read(object="group:", relation="member", user=ids.user(user_id))
    desired = {group_role(ids.parse_group(item.object)) for item in members}
    async with conn.transaction():
        cursor = await conn.execute(_MEMBERSHIPS_OF.format(Literal(role)))
        rows = await cursor.fetchall()
    current = {group for group, _, _ in rows}
    inheriting = {group for group, inherit, _ in rows if inherit}
    # A revoke would try every grantor; only admin-granted drift is ours to remove.
    foreign = {group for group, _, grantor in rows if grantor != conn.info.user}
    ops: list[GrantMembership | RevokeMembership] = [
        GrantMembership(group, role) for group in sorted(desired - inheriting)
    ]
    ops.extend(RevokeMembership(group, role) for group in sorted(current - desired - foreign))
    if ops:
        await executor.apply(connection, ops)


async def sync_user_memberships(
    store: PermissionStore,
    executor: Executor,
    locks: ConnectionLocks,
    connection: str,
    user_id: int,
    *,
    conn: psycopg.AsyncConnection,
) -> None:
    """Make ``u_<user_id>``'s ``g_*`` memberships equal its OpenFGA groups.

    Reads the current membership from the caller's idle admin connection:
    the ``Executor`` protocol only exposes ``apply``, so the factory behind
    ``PgExecutor`` is not reachable here. Holds ``locks(connection)`` so it
    never interleaves with the Syncer, the Reconciler or an inline revoke
    (plan §2.7 point 5).
    """
    async with locks(connection):
        await _sync_memberships(conn, store, executor, connection, user_id)


async def on_session_start(
    conn: psycopg.AsyncConnection,
    store: PermissionStore,
    executor: Executor,
    locks: ConnectionLocks,
    connection: str,
    user_id: int,
) -> None:
    """Run both provisioning steps for one session start, under one lock hold.

    M1 calls this with a fresh idle admin connection to ``connection`` when a
    user's session begins.
    """
    async with locks(connection):
        await ensure_user_role(conn, user_id)
        await _sync_memberships(conn, store, executor, connection, user_id)
