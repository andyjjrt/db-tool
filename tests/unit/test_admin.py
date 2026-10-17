"""Unit tests for the admin rules (plan §2.8)."""

from collections.abc import Iterable, Sequence

import pytest

from db_gateway.permissions import admin, ids
from db_gateway.permissions.store import (
    ChangesPage,
    PermissionStore,
    PermissionStoreUnavailable,
    Tuple,
)


class FakeStore(PermissionStore):
    """Tiny in-memory store; these tests exercise check and read only."""

    def __init__(self, admin_ids: Iterable[int] = (), tuples: Iterable[Tuple] = ()) -> None:
        self.admin_ids = set(admin_ids)
        self.tuples = list(tuples)
        self.checks: list[tuple[str, str, str]] = []
        self.reads: list[tuple[str | None, str | None, str | None]] = []
        self.unavailable = False

    async def check(self, user: str, relation: str, object: str) -> bool:
        self.checks.append((user, relation, object))
        if self.unavailable:
            raise PermissionStoreUnavailable("store down")
        return user in {ids.user(user_id) for user_id in self.admin_ids}

    async def read(
        self, object: str | None = None, relation: str | None = None, user: str | None = None
    ) -> list[Tuple]:
        self.reads.append((object, relation, user))
        return [
            t
            for t in self.tuples
            if (object is None or t.object == object)
            and (relation is None or t.relation == relation)
            and (user is None or t.user == user)
        ]

    async def write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
        raise NotImplementedError

    async def read_changes(
        self, continuation_token: str | None, page_size: int = 100
    ) -> ChangesPage:
        raise NotImplementedError


def test_admin_tuple_matches_the_written_form() -> None:
    assert admin.admin_tuple(12) == Tuple(user="user:12", relation="admin", object="gateway:main")


def test_regular_admin_cannot_remove_or_disable_an_admin() -> None:
    initial = frozenset({"root"})
    sam = admin.AdminUser(id=7, login_key="sam")
    kim = admin.AdminUser(id=8, login_key="kim")
    with pytest.raises(admin.AdminForbidden):
        admin.ensure_can_remove_admin(sam, kim, initial_admins=initial)
    with pytest.raises(admin.AdminForbidden):
        admin.ensure_can_disable_user(sam, kim, target_is_admin=True, initial_admins=initial)


def test_initial_admin_can_remove_and_disable_a_regular_admin() -> None:
    initial = frozenset({"root"})
    root = admin.AdminUser(id=1, login_key="root")
    sam = admin.AdminUser(id=7, login_key="sam")
    admin.ensure_can_remove_admin(root, sam, initial_admins=initial)
    admin.ensure_can_disable_user(root, sam, target_is_admin=True, initial_admins=initial)


def test_initial_admin_can_never_be_removed_or_disabled() -> None:
    initial = frozenset({"root", "boss"})
    root = admin.AdminUser(id=1, login_key="root")
    boss = admin.AdminUser(id=2, login_key="boss")  # another initial admin
    sam = admin.AdminUser(id=7, login_key="sam")  # an ordinary admin
    for caller in (root, boss, sam):
        with pytest.raises(admin.AdminForbidden):
            admin.ensure_can_remove_admin(caller, root, initial_admins=initial)
        with pytest.raises(admin.AdminForbidden):
            admin.ensure_can_disable_user(
                caller, root, target_is_admin=True, initial_admins=initial
            )


def test_disabling_a_non_admin_needs_no_admin_rule() -> None:
    initial = frozenset({"root"})
    sam = admin.AdminUser(id=7, login_key="sam")
    mira = admin.AdminUser(id=8, login_key="mira")
    # No raise: who may disable plain users is decided outside these rules.
    admin.ensure_can_disable_user(sam, mira, target_is_admin=False, initial_admins=initial)


def test_only_admins_may_add_admins() -> None:
    with pytest.raises(admin.AdminForbidden):
        admin.ensure_can_add_admin(False)
    admin.ensure_can_add_admin(True)


async def test_initial_admin_is_admin_without_a_store_call() -> None:
    store = FakeStore()
    checker = admin.AdminChecker(store, initial_admins=frozenset({"root"}))
    assert await checker.is_admin(admin.AdminUser(id=1, login_key="root")) is True
    assert store.checks == []


async def test_stored_admin_and_non_admin_via_store_are_cached() -> None:
    store = FakeStore(admin_ids={7})
    checker = admin.AdminChecker(store, initial_admins=frozenset({"root"}))
    sam = admin.AdminUser(id=7, login_key="sam")
    mira = admin.AdminUser(id=8, login_key="mira")
    assert await checker.is_admin(sam) is True
    assert await checker.is_admin(sam) is True
    assert await checker.is_admin(mira) is False
    assert await checker.is_admin(mira) is False
    assert store.checks == [
        ("user:7", "admin", "gateway:main"),
        ("user:8", "admin", "gateway:main"),
    ]


async def test_store_unavailable_propagates_and_is_not_cached() -> None:
    store = FakeStore()
    store.unavailable = True
    checker = admin.AdminChecker(store, initial_admins=frozenset({"root"}))
    sam = admin.AdminUser(id=7, login_key="sam")
    with pytest.raises(PermissionStoreUnavailable):
        await checker.is_admin(sam)
    assert len(store.checks) == 1
    store.unavailable = False
    store.admin_ids.add(7)
    assert await checker.is_admin(sam) is True
    assert len(store.checks) == 2


async def test_list_admins_merges_both_sources_and_dedupes() -> None:
    store = FakeStore(
        tuples=[
            admin.admin_tuple(3),
            admin.admin_tuple(5),
            admin.admin_tuple(5),  # the same admin stored twice collapses to one entry
            Tuple(user="user:9", relation="reader", object=ids.GATEWAY_MAIN),  # other relation
        ]
    )
    entries = await admin.list_admins(store, initial_admins=frozenset({"root", "boss"}))
    assert store.reads == [(ids.GATEWAY_MAIN, "admin", None)]
    assert entries == [
        admin.AdminEntry(login_key="boss", user_id=None, initial=True),
        admin.AdminEntry(login_key="root", user_id=None, initial=True),
        admin.AdminEntry(login_key=None, user_id=3, initial=False),
        admin.AdminEntry(login_key=None, user_id=5, initial=False),
    ]
