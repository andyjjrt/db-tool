"""Integration tests for the provisioner: personal roles and session memberships.

Real PG through the ``target_admin`` fixture (a CREATEROLE login that owns the
database), a ``MemoryStore`` for the OpenFGA side and the real ``PgExecutor``
for membership changes.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import psycopg
import pytest
from psycopg.sql import SQL, Identifier, Literal

from db_gateway.permissions import ids
from db_gateway.permissions.context import ConnectionLocks
from db_gateway.permissions.executor import PgExecutor
from db_gateway.permissions.store import Tuple
from db_gateway.permissions.store_memory import MemoryStore
from db_gateway.permissions.types import CreateGroupRole, group_role, user_role
from db_gateway.provisioner import ensure_user_role, on_session_start, sync_user_memberships
from tests.conftest import RoleInfo
from tests.integration.test_target_db import TargetAdmin
from tests.integration.test_target_db import target_admin as target_admin

pytestmark = pytest.mark.integration

CONNECTION = "target"


@dataclass(frozen=True, slots=True)
class ProvisionerTarget:
    admin: TargetAdmin
    store: MemoryStore
    executor: PgExecutor
    locks: ConnectionLocks
    connect: Callable[[str], Awaitable[psycopg.AsyncConnection]]


@pytest.fixture
def provisioner_target(
    cluster_lock: psycopg.AsyncConnection | None,
    target_admin: TargetAdmin,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
) -> ProvisionerTarget:
    async def connect(name: str) -> psycopg.AsyncConnection:
        assert name == CONNECTION
        return await connect_as(target_admin.login)

    return ProvisionerTarget(
        admin=target_admin,
        store=MemoryStore(),
        executor=PgExecutor(connect),
        locks=ConnectionLocks(),
        connect=connect,
    )


async def _group_memberships(conn: psycopg.AsyncConnection, member: str) -> set[str]:
    """The names of the g_* roles ``member`` belongs to (pg_auth_members)."""
    cursor = await conn.execute(
        SQL(
            "SELECT g.rolname FROM pg_catalog.pg_auth_members m "
            "JOIN pg_catalog.pg_roles g ON g.oid = m.roleid "
            "JOIN pg_catalog.pg_roles u ON u.oid = m.member "
            "WHERE u.rolname = {} AND left(g.rolname, 2) = 'g_'"
        ).format(Literal(member))
    )
    return {row[0] for row in await cursor.fetchall()}


async def _gw_managed_membership(
    conn: psycopg.AsyncConnection, member: str
) -> list[tuple[object, ...]]:
    """Admin/inherit/set flags and grantor of ``member``'s gw_managed membership."""
    cursor = await conn.execute(
        SQL(
            "SELECT m.admin_option, m.inherit_option, m.set_option, grantor.rolname "
            "FROM pg_catalog.pg_auth_members m "
            "JOIN pg_catalog.pg_roles g ON g.oid = m.roleid "
            "JOIN pg_catalog.pg_roles u ON u.oid = m.member "
            "JOIN pg_catalog.pg_roles grantor ON grantor.oid = m.grantor "
            "WHERE g.rolname = 'gw_managed' AND u.rolname = {}"
        ).format(Literal(member))
    )
    return [tuple(row) for row in await cursor.fetchall()]


async def _role_state(conn: psycopg.AsyncConnection, role: str) -> tuple[object, ...]:
    """Role attributes plus every membership row the role appears in.

    A second provisioning call must leave this snapshot exactly as it was.
    """
    cursor = await conn.execute(
        SQL(
            "SELECT rolcanlogin, rolinherit, rolsuper, rolcreaterole, rolbypassrls "
            "FROM pg_catalog.pg_roles WHERE rolname = {}"
        ).format(Literal(role))
    )
    attributes = await cursor.fetchone()
    assert attributes is not None
    cursor = await conn.execute(
        SQL(
            "SELECT g.rolname, u.rolname, grantor.rolname, m.admin_option, "
            "m.inherit_option, m.set_option "
            "FROM pg_catalog.pg_auth_members m "
            "JOIN pg_catalog.pg_roles g ON g.oid = m.roleid "
            "JOIN pg_catalog.pg_roles u ON u.oid = m.member "
            "JOIN pg_catalog.pg_roles grantor ON grantor.oid = m.grantor "
            "WHERE g.rolname = {} OR u.rolname = {} ORDER BY 1, 2, 3"
        ).format(Literal(role), Literal(role))
    )
    return (attributes, tuple(await cursor.fetchall()))


async def test_ensure_user_role_creates_a_managed_login(
    provisioner_target: ProvisionerTarget,
    superuser_conn: psycopg.AsyncConnection,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
) -> None:
    target = provisioner_target
    user_id = secrets.randbits(48)
    role = user_role(user_id)

    async with await target.connect(CONNECTION) as admin:
        await ensure_user_role(admin, user_id)

        cursor = await admin.execute(
            SQL(
                "SELECT rolcanlogin, rolinherit FROM pg_catalog.pg_roles WHERE rolname = {}"
            ).format(Literal(role))
        )
        assert await cursor.fetchone() == (True, True)
        assert await _gw_managed_membership(admin, role) == [
            (False, True, True, target.admin.login.name)
        ]

        before = await _role_state(admin, role)
        await ensure_user_role(admin, user_id)
        assert await _role_state(admin, role) == before

    # M1 owns credentials; the test sets a password as superuser to log in.
    password = secrets.token_hex(12)
    await superuser_conn.execute(
        SQL("ALTER ROLE {} PASSWORD {}").format(Identifier(role), Literal(password))
    )
    async with await connect_as(RoleInfo(role, password)) as session:
        cursor = await session.execute("SELECT session_user, gateway_acl.is_managed()")
        assert await cursor.fetchone() == (role, True)

        # The admin account is never altered, not even when it happens to be
        # the personal role itself.
        with pytest.raises(ValueError, match="admin account"):
            await ensure_user_role(session, user_id)


async def test_existing_noinherit_role_is_fixed(provisioner_target: ProvisionerTarget) -> None:
    target = provisioner_target
    user_id = secrets.randbits(48)
    role = user_role(user_id)

    async with await target.connect(CONNECTION) as admin:
        # The role exists from an earlier session with the wrong attributes,
        # and its gw_managed membership does not inherit.
        await admin.execute(SQL("CREATE ROLE {} LOGIN NOINHERIT").format(Identifier(role)))
        await admin.execute(
            SQL("GRANT gw_managed TO {} WITH INHERIT FALSE").format(Identifier(role))
        )

        await ensure_user_role(admin, user_id)

        cursor = await admin.execute(
            SQL(
                "SELECT rolcanlogin, rolinherit FROM pg_catalog.pg_roles WHERE rolname = {}"
            ).format(Literal(role))
        )
        assert await cursor.fetchone() == (True, True)
        rows = await _gw_managed_membership(admin, role)
        assert [(inherit, granted_by) for _, inherit, _, granted_by in rows] == [
            (True, target.admin.login.name)
        ]


async def test_sync_user_memberships_tracks_openfga(
    provisioner_target: ProvisionerTarget,
    unique_name: Callable[[str], str],
) -> None:
    target = provisioner_target
    user_id = secrets.randbits(48)
    role = user_role(user_id)
    first, second, extra = [unique_name("grp") for _ in range(3)]
    await target.executor.apply(
        CONNECTION, [CreateGroupRole(group_role(name)) for name in (first, second, extra)]
    )
    member = Tuple(ids.user(user_id), "member", ids.group(first))
    await target.store.write([member])

    async with await target.connect(CONNECTION) as admin:
        await ensure_user_role(admin, user_id)
        await sync_user_memberships(
            target.store, target.executor, target.locks, CONNECTION, user_id, conn=admin
        )
        assert await _group_memberships(admin, role) == {group_role(first)}

        # Add a second group and remove the first in OpenFGA, then sync again.
        await target.store.write([Tuple(ids.user(user_id), "member", ids.group(second))], [member])
        await sync_user_memberships(
            target.store, target.executor, target.locks, CONNECTION, user_id, conn=admin
        )
        assert await _group_memberships(admin, role) == {group_role(second)}

        # A membership granted outside OpenFGA is extra and gets revoked.
        await admin.execute(
            SQL("GRANT {} TO {}").format(Identifier(group_role(extra)), Identifier(role))
        )
        assert await _group_memberships(admin, role) == {group_role(second), group_role(extra)}
        await sync_user_memberships(
            target.store, target.executor, target.locks, CONNECTION, user_id, conn=admin
        )
        assert await _group_memberships(admin, role) == {group_role(second)}
        # gw_managed is not a group: it must survive the sync untouched.
        assert await _gw_managed_membership(admin, role) == [
            (False, True, True, target.admin.login.name)
        ]


async def test_create_role_does_not_make_the_admin_a_member(
    provisioner_target: ProvisionerTarget,
) -> None:
    target = provisioner_target
    user_id = secrets.randbits(48)
    role = user_role(user_id)

    async with await target.connect(CONNECTION) as admin:
        # Without clearing it per transaction, PostgreSQL would self-grant
        # 'set, inherit' membership to the creating admin account.
        await admin.execute(SQL("SET createrole_self_grant = 'set, inherit'"))
        await ensure_user_role(admin, user_id)
        cursor = await admin.execute(
            SQL(
                "SELECT m.admin_option, m.inherit_option, m.set_option "
                "FROM pg_catalog.pg_auth_members m "
                "JOIN pg_catalog.pg_roles g ON g.oid = m.roleid "
                "JOIN pg_catalog.pg_roles u ON u.oid = m.member "
                "WHERE g.rolname = {} AND u.rolname = {}"
            ).format(Literal(role), Literal(target.admin.login.name))
        )
        assert await cursor.fetchall() == [(True, False, False)]
        cursor = await admin.execute(
            SQL(
                "SELECT pg_catalog.pg_has_role(current_user, {}, 'USAGE'), "
                "pg_catalog.pg_has_role(current_user, {}, 'SET')"
            ).format(Literal(role), Literal(role))
        )
        assert await cursor.fetchone() == (False, False)


async def test_on_session_start_creates_role_and_memberships(
    provisioner_target: ProvisionerTarget,
    unique_name: Callable[[str], str],
) -> None:
    target = provisioner_target
    user_id = secrets.randbits(48)
    role = user_role(user_id)
    name = unique_name("grp")
    await target.executor.apply(CONNECTION, [CreateGroupRole(group_role(name))])
    await target.store.write([Tuple(ids.user(user_id), "member", ids.group(name))])

    async with await target.connect(CONNECTION) as admin:
        await on_session_start(
            admin, target.store, target.executor, target.locks, CONNECTION, user_id
        )
        cursor = await admin.execute(
            SQL(
                "SELECT rolcanlogin, rolinherit FROM pg_catalog.pg_roles WHERE rolname = {}"
            ).format(Literal(role))
        )
        assert await cursor.fetchone() == (True, True)
        assert await _group_memberships(admin, role) == {group_role(name)}

        before = await _role_state(admin, role)
        await on_session_start(
            admin, target.store, target.executor, target.locks, CONNECTION, user_id
        )
        assert await _role_state(admin, role) == before


async def test_non_inheriting_group_membership_is_repaired_on_session_start(
    provisioner_target: ProvisionerTarget,
    superuser_conn: psycopg.AsyncConnection,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    unique_name: Callable[[str], str],
) -> None:
    target = provisioner_target
    user_id = secrets.randbits(48)
    role = user_role(user_id)
    name = unique_name("grp")
    group = group_role(name)
    schema = Identifier(target.admin.schema, "t")
    await target.executor.apply(CONNECTION, [CreateGroupRole(group)])
    await target.store.write([Tuple(ids.user(user_id), "member", ids.group(name))])
    password = secrets.token_hex(12)

    async with await target.connect(CONNECTION) as admin:
        await admin.execute(SQL("CREATE TABLE {} (x int)").format(schema))
        await admin.execute(SQL("GRANT SELECT ON {} TO {}").format(schema, Identifier(group)))
        await on_session_start(
            admin, target.store, target.executor, target.locks, CONNECTION, user_id
        )
        await superuser_conn.execute(
            SQL("ALTER ROLE {} PASSWORD {}").format(Identifier(role), Literal(password))
        )

        async def can_read() -> bool:
            async with await connect_as(RoleInfo(role, password)) as session:
                try:
                    await session.execute(SQL("SELECT * FROM {}").format(schema))
                except psycopg.errors.InsufficientPrivilege:
                    return False
                return True

        assert await can_read()
        await admin.execute(
            SQL("GRANT {} TO {} WITH INHERIT FALSE, SET FALSE").format(
                Identifier(group), Identifier(role)
            )
        )
        assert not await can_read()
        await on_session_start(
            admin, target.store, target.executor, target.locks, CONNECTION, user_id
        )
        assert await can_read()


async def test_sync_never_touches_a_foreign_grantor_membership(
    provisioner_target: ProvisionerTarget,
    superuser_conn: psycopg.AsyncConnection,
    unique_name: Callable[[str], str],
) -> None:
    target = provisioner_target
    user_id = secrets.randbits(48)
    role = user_role(user_id)
    group = group_role(unique_name("grp"))
    await target.executor.apply(CONNECTION, [CreateGroupRole(group)])
    async with await target.connect(CONNECTION) as admin:
        await ensure_user_role(admin, user_id)
        await superuser_conn.execute(
            SQL("GRANT {} TO {}").format(Identifier(group), Identifier(role))
        )
        await sync_user_memberships(
            target.store, target.executor, target.locks, CONNECTION, user_id, conn=admin
        )
        assert await _group_memberships(admin, role) == {group}


async def test_sync_refuses_the_admin_account_itself(
    provisioner_target: ProvisionerTarget,
    superuser_conn: psycopg.AsyncConnection,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    unique_name: Callable[[str], str],
) -> None:
    target = provisioner_target
    user_id = secrets.randbits(48)
    role = user_role(user_id)
    name = unique_name("grp")
    await target.executor.apply(CONNECTION, [CreateGroupRole(group_role(name))])
    await target.store.write([Tuple(ids.user(user_id), "member", ids.group(name))])
    password = secrets.token_hex(12)
    await superuser_conn.execute(
        SQL("CREATE ROLE {} LOGIN CREATEROLE PASSWORD {}").format(
            Identifier(role), Literal(password)
        )
    )
    applied: list[object] = []

    class Recording:
        async def apply(self, connection: str, ops: object) -> list[object]:
            applied.append(ops)
            return []

    try:
        async with await connect_as(RoleInfo(role, password)) as conn:
            with pytest.raises(ValueError, match="admin account"):
                await sync_user_memberships(
                    target.store,
                    Recording(),  # type: ignore[arg-type]
                    target.locks,
                    CONNECTION,
                    user_id,
                    conn=conn,
                )
            with pytest.raises(ValueError, match="admin account"):
                await on_session_start(
                    conn,
                    target.store,
                    Recording(),  # type: ignore[arg-type]
                    target.locks,
                    CONNECTION,
                    user_id,
                )
    finally:
        await superuser_conn.execute(SQL("DROP ROLE IF EXISTS {}").format(Identifier(role)))
    assert applied == []
