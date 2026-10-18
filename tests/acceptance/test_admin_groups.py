"""Plan §5 admin (§2.8) and groups (§11)."""

import pytest
from psycopg.sql import SQL, Identifier

from db_gateway.permissions.admin import (
    AdminChecker,
    AdminForbidden,
    ensure_can_disable_user,
)
from db_gateway.permissions.types import group_role
from tests.acceptance.conftest import CONNECTION, INITIAL_ADMIN_KEY, Stack


async def test_s5_ordinary_admin_cannot_remove_an_admin(stack: Stack) -> None:
    """§5 admin: an ordinary admin removing an admin -> AdminForbidden (403)."""
    first, second = await stack.new_user("adm"), await stack.new_user("adm")
    for person in (first, second):
        await stack.rules.add_admin(stack.actor, person.id)
    checker = AdminChecker(stack.store, frozenset({INITIAL_ADMIN_KEY}))
    assert await checker.is_admin(first.admin_user)
    with pytest.raises(AdminForbidden):
        await stack.rules.remove_admin(first.admin_user, second.id)
    assert await AdminChecker(stack.store, frozenset({INITIAL_ADMIN_KEY})).is_admin(
        second.admin_user
    )


async def test_s5_ordinary_admin_cannot_disable_an_admin_account(stack: Stack) -> None:
    """§5 admin: an ordinary admin disabling an admin account -> AdminForbidden (403)."""
    first, second = await stack.new_user("adm"), await stack.new_user("adm")
    initial = frozenset({INITIAL_ADMIN_KEY})
    with pytest.raises(AdminForbidden):
        ensure_can_disable_user(first.admin_user, second.admin_user, True, initial)
    # Disabling a non-admin has no admin-specific rule.
    ensure_can_disable_user(first.admin_user, second.admin_user, False, initial)


async def test_s5_initial_admin_can_remove_and_disable_ordinary_admin(stack: Stack) -> None:
    """§5 admin: the initial admin can remove an admin and disable an admin account."""
    ordinary = await stack.new_user("adm")
    await stack.rules.add_admin(stack.actor, ordinary.id)
    ensure_can_disable_user(stack.actor, ordinary.admin_user, True, frozenset({INITIAL_ADMIN_KEY}))
    await stack.rules.remove_admin(stack.actor, ordinary.id)
    assert not await AdminChecker(stack.store, frozenset({INITIAL_ADMIN_KEY})).is_admin(
        ordinary.admin_user
    )


async def test_s5_initial_admin_cannot_be_removed_or_disabled(stack: Stack) -> None:
    """§5 admin: nobody -- not even an initial admin -- can remove or disable an initial admin."""
    ordinary = await stack.new_user("adm")
    await stack.rules.add_admin(stack.actor, ordinary.id)
    with pytest.raises(AdminForbidden):
        await stack.rules.remove_admin(stack.actor, stack.actor.id)
    with pytest.raises(AdminForbidden):
        await stack.rules.remove_admin(ordinary.admin_user, stack.actor.id)
    initial = frozenset({INITIAL_ADMIN_KEY})
    for caller in (stack.actor, ordinary.admin_user):
        with pytest.raises(AdminForbidden):
            ensure_can_disable_user(caller, stack.actor, True, initial)


async def test_s11_create_group_creates_role_after_sync(stack: Stack) -> None:
    """§11 groups: creating a group -> the g_* role exists once the Syncer has run."""
    name = stack.unique_name("newgrp")
    await stack.rules.create_group(stack.actor, name)
    assert not await stack.role_exists(group_role(name))
    await stack.sync()
    assert await stack.role_exists(group_role(name))


async def test_s11_delete_group_is_synced_and_role_is_gone(stack: Stack) -> None:
    """§11 groups: deleting a rule-free group -> `synced` and the g_* role is dropped."""
    user = await stack.new_user()
    name = await stack.new_group("delgrp", user)
    assert await stack.role_exists(group_role(name))
    assert await stack.rules.delete_group(stack.actor, name) == "synced"
    assert not await stack.role_exists(group_role(name))
    assert await stack.rules.list_groups() == []
    await stack.sync()
    assert not await stack.role_exists(group_role(name))


async def test_s11_reconcile_drops_orphan_group_role(stack: Stack) -> None:
    """§11 groups: a g_* role with no group tuple in OpenFGA is dropped by reconcile."""
    orphan = group_role(stack.unique_name("orphan"))
    await stack.admin_sql(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(orphan)))
    assert await stack.role_exists(orphan)
    report = await stack.reconciler.reconcile_strict(CONNECTION)
    assert any(getattr(op, "role", None) == orphan for op in report.fixes)
    assert not await stack.role_exists(orphan)
