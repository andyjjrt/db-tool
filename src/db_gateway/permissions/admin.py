"""Admin rules (plan §2.8): who is an admin, and who may change that.

``INITIAL_ADMINS`` is a code constant, not configuration: it is edited in
code and redeployed, and deliberately not read from the environment. Initial
admins are always admins; they are not stored in OpenFGA, can never be
removed from the admin group and can never have their account disabled --
not even by another initial admin. Everyone else with an ``admin`` relation
on ``gateway:main`` is an ordinary admin: ordinary admins may add admins, but
only an initial admin may remove an admin or disable an admin's account.

The ``ensure_*`` functions are pure and raise :class:`AdminForbidden` (the
API maps it to 403); :class:`AdminChecker` and :func:`list_admins` talk to
the ``PermissionStore``.
"""

from collections.abc import Set
from dataclasses import dataclass

from db_gateway.permissions import ids
from db_gateway.permissions.store import PermissionStore, Tuple

# Login keys of the initial administrators, edited in code on purpose: gaining
# this power is meant to be a code change plus a redeploy, not something the
# running system can hand out.
INITIAL_ADMINS: frozenset[str] = frozenset({"andyjjrt"})

ADMIN_RELATION = "admin"


class AdminForbidden(Exception):
    """The caller may not perform this admin operation; the API maps it to 403."""


@dataclass(frozen=True, slots=True)
class AdminUser:
    """A user as the admin rules identify them: users.id plus users.login_key."""

    id: int
    login_key: str


def admin_tuple(user_id: int) -> Tuple:
    """The stored admin tuple for a user: gateway:main#admin@user:<id>."""
    return Tuple(user=ids.user(user_id), relation=ADMIN_RELATION, object=ids.GATEWAY_MAIN)


class AdminChecker:
    """Answers "is this user an admin?", caching the answers for its lifetime.

    One instance per request, built with the request's store. Tests pass an
    ``initial_admins`` override instead of patching the module constant.
    ``PermissionStoreUnavailable`` propagates to the caller; a failed check is
    not cached.
    """

    def __init__(self, store: PermissionStore, initial_admins: Set[str] = INITIAL_ADMINS) -> None:
        self._store = store
        self._initial_admins = initial_admins
        self._cache: dict[int, bool] = {}

    async def is_admin(self, user: AdminUser) -> bool:
        """True for initial admins (no store call) and for stored admins."""
        if user.login_key in self._initial_admins:
            return True
        cached = self._cache.get(user.id)
        if cached is None:
            cached = await self._store.check(ids.user(user.id), ADMIN_RELATION, ids.GATEWAY_MAIN)
            self._cache[user.id] = cached
        return cached


def ensure_can_remove_admin(
    caller: AdminUser,
    target: AdminUser,
    initial_admins: Set[str] = INITIAL_ADMINS,
) -> None:
    """Only an initial admin may remove an admin, and never an initial admin."""
    if caller.login_key not in initial_admins:
        raise AdminForbidden("only an initial admin may remove an admin")
    if target.login_key in initial_admins:
        raise AdminForbidden("an initial admin can never be removed from admins")


def ensure_can_disable_user(
    caller: AdminUser,
    target: AdminUser,
    target_is_admin: bool,
    initial_admins: Set[str] = INITIAL_ADMINS,
) -> None:
    """Disabling an admin's account requires an initial-admin caller.

    An initial admin can never be disabled. Non-admin targets have no rule
    here: the caller's ordinary right to disable accounts is enforced
    elsewhere.
    """
    if target.login_key in initial_admins:
        raise AdminForbidden("an initial admin can never be disabled")
    if target_is_admin and caller.login_key not in initial_admins:
        raise AdminForbidden("only an initial admin may disable an admin account")


def ensure_can_add_admin(caller_is_admin: bool) -> None:
    """Any admin -- initial or stored -- may add admins."""
    if not caller_is_admin:
        raise AdminForbidden("only an admin may add admins")


@dataclass(frozen=True, slots=True)
class AdminEntry:
    """One admin of the merged list, from exactly one of the two sources.

    Initial admins are known by ``login_key`` and have ``user_id=None`` (their
    users row is not looked up here); stored admins are known by ``user_id``
    and have ``login_key=None``.
    """

    login_key: str | None
    user_id: int | None
    initial: bool


async def list_admins(
    store: PermissionStore, initial_admins: Set[str] = INITIAL_ADMINS
) -> list[AdminEntry]:
    """Every admin, for GET /api/admin/admins.

    The union of the initial admins (one entry per login_key, flagged
    ``initial=True``) and the stored admin tuples (one entry per user id,
    flagged ``initial=False``; repeated tuples collapse). Order is stable:
    initial admins sorted by login_key first, then stored admins sorted by
    user id. Someone who is both an initial admin and has their own stored
    tuple appears once per source; the endpoint joins on the users table if
    it wants a single row per person.
    """
    entries = [
        AdminEntry(login_key=login_key, user_id=None, initial=True)
        for login_key in sorted(initial_admins)
    ]
    seen: set[int] = set()
    stored: list[int] = []
    for tuple_ in await store.read(ids.GATEWAY_MAIN, ADMIN_RELATION):
        user_id = ids.parse_user(tuple_.user)
        if user_id not in seen:
            seen.add(user_id)
            stored.append(user_id)
    entries.extend(
        AdminEntry(login_key=None, user_id=user_id, initial=False) for user_id in sorted(stored)
    )
    return entries
