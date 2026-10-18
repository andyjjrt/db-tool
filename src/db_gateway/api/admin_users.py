"""Admin user management: register, list, read, update, disable and enable users.

Identity comes only from the :func:`db_gateway.api.auth.require_admin` boundary
(the OIDC web session, elsewhere). ``login_key`` is the OIDC login claim value:
it is stored stripped, case-sensitive, and it -- not ``users.id`` -- is what
``INITIAL_ADMINS`` matches, so a rename that would hand out or strip
initial-admin power is refused (403).

Disabling is only a metadata write: ``current_user`` re-checks
``users.disabled_at`` on every request, so it takes effect on the target's next
request; terminating the user's PostgreSQL sessions is a later milestone.

Audit: every accepted write call records exactly one ``admin`` row in the same
``metadata.transaction`` as the row change. An idempotent disable/enable/unbind
is still an admin action and is audited even though the ``users`` row is unchanged.

The disable and unbind routes gate on the target's admin status, so they evaluate
it twice: a fast check outside the lock and the authoritative check under the
``RuleService`` lock that admin promotion and removal hold. A promotion landing
after the fast check is therefore still seen before the write (gate finding M3).
Their state changes are unconditional idempotent writes re-read inside the
``metadata.transaction``, so a binding or flag committed by another request
while the checks run is still reflected in the response and the audit row
(gate2 finding G2-4).
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, field_validator

from db_gateway import metadata
from db_gateway.api.auth import permission_store, require_admin
from db_gateway.metadata import audit, users
from db_gateway.metadata.users import UserRow
from db_gateway.permissions.admin import (
    INITIAL_ADMINS,
    AdminChecker,
    AdminForbidden,
    AdminUser,
    ensure_can_disable_user,
)
from db_gateway.permissions.ids import InvalidInput
from db_gateway.permissions.rules import NotFound, RuleConflict
from db_gateway.permissions.store import PermissionStore

router = APIRouter(prefix="/api/admin/users", tags=["admin"])
Actor = Annotated[AdminUser, Depends(require_admin)]
Store = Annotated[PermissionStore, Depends(permission_store)]

MAX_LOGIN_KEY_LEN = 255


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


def clean_login_key(value: str) -> str:
    """Strip a login key and reject empty, over-long, whitespace or control input."""
    login_key = value.strip()
    if not login_key:
        raise InvalidInput("login_key must not be empty")
    if len(login_key) > MAX_LOGIN_KEY_LEN:
        raise InvalidInput(f"login_key must be at most {MAX_LOGIN_KEY_LEN} characters")
    if any(char.isspace() or not char.isprintable() for char in login_key):
        raise InvalidInput("login_key must not contain whitespace or control characters")
    return login_key


class UserCreate(Input):
    login_key: str
    email: str | None = None
    display_name: str | None = None

    @field_validator("login_key")
    @classmethod
    def _clean(cls, value: str) -> str:
        return clean_login_key(value)


class UserPatch(Input):
    login_key: str | None = None
    email: str | None = None
    display_name: str | None = None

    @field_validator("login_key")
    @classmethod
    def _clean(cls, value: str | None) -> str:
        if value is None:
            raise InvalidInput("login_key cannot be cleared")
        return clean_login_key(value)


def user_body(row: UserRow, is_admin: bool) -> dict[str, Any]:
    return {
        "id": row.id,
        "login_key": row.login_key,
        "email": row.email,
        "display_name": row.display_name,
        "disabled_at": row.disabled_at,
        "oidc_bound": row.oidc_sub is not None,
        "is_admin": is_admin,
        "is_initial_admin": row.login_key in INITIAL_ADMINS,
        "created_at": row.created_at,
    }


async def user_view(row: UserRow, checker: AdminChecker) -> dict[str, Any]:
    return user_body(row, is_admin=await checker.is_admin(AdminUser(row.id, row.login_key)))


def ensure_can_unbind_user(caller: AdminUser, target: AdminUser, target_is_admin: bool) -> None:
    """An initial admin's subject is pinned in code and is never unbound.

    Unbinding another admin's account requires an initial-admin caller, the same
    spirit as disabling one.
    """
    if target.login_key in INITIAL_ADMINS:
        raise AdminForbidden("an initial admin's OIDC subject is pinned in code")
    if target_is_admin and caller.login_key not in INITIAL_ADMINS:
        raise AdminForbidden("only an initial admin may unbind an admin account")


@router.get("")
async def list_users(
    request: Request, actor: Actor, store: Store, include_disabled: bool = True
) -> list[dict[str, Any]]:
    """Every user ordered by login_key; disabled accounts included by default."""
    checker = AdminChecker(store)
    return [
        await user_view(row, checker)
        for row in await users.list(request.app.state.metadata, include_disabled=include_disabled)
    ]


@router.post("", status_code=201)
async def create_user(
    body: UserCreate, request: Request, actor: Actor, store: Store
) -> dict[str, Any]:
    """Register a user; the login flow refuses unknown and disabled users."""
    db = request.app.state.metadata
    async with metadata.transaction(db):
        if await users.get_by_login_key(db, body.login_key) is not None:
            raise RuleConflict(f"user already exists: {body.login_key}")
        row = await users.insert(
            db, body.login_key, email=body.email, display_name=body.display_name
        )
        await audit.record(
            db,
            "admin",
            user_id=actor.id,
            detail={"action": "create_user", "target_user_id": row.id, "login_key": row.login_key},
        )
    return await user_view(row, AdminChecker(store))


@router.get("/{user_id}")
async def get_user(user_id: int, request: Request, actor: Actor, store: Store) -> dict[str, Any]:
    row = await users.get_by_id(request.app.state.metadata, user_id)
    if row is None:
        raise NotFound(f"user not found: {user_id}")
    return await user_view(row, AdminChecker(store))


@router.patch("/{user_id}")
async def update_user(
    user_id: int, body: UserPatch, request: Request, actor: Actor, store: Store
) -> dict[str, Any]:
    """Update the supplied fields; an initial-admin login_key is never renamed in or out."""
    db = request.app.state.metadata
    changes: dict[str, str | None] = {
        name: getattr(body, name)
        for name in ("login_key", "email", "display_name")
        if name in body.model_fields_set
    }
    async with metadata.transaction(db):
        row = await users.get_by_id(db, user_id)
        if row is None:
            raise NotFound(f"user not found: {user_id}")
        renamed = changes.get("login_key")
        if renamed is not None and renamed != row.login_key:
            if row.login_key in INITIAL_ADMINS or renamed in INITIAL_ADMINS:
                raise AdminForbidden(
                    "an initial-admin login_key cannot be renamed in or out: "
                    f"{row.login_key!r} -> {renamed!r}"
                )
            if await users.get_by_login_key(db, renamed) is not None:
                raise RuleConflict(f"user already exists: {renamed}")
        if renamed == row.login_key:
            del changes["login_key"]
        updated = await users.update(db, user_id, changes)
        assert updated is not None
        await audit.record(
            db,
            "admin",
            user_id=actor.id,
            detail={"action": "update_user", "target_user_id": user_id, "changes": changes},
        )
    return await user_view(updated, AdminChecker(store))


@router.post("/{user_id}/disable")
async def disable_user(
    user_id: int, request: Request, actor: Actor, store: Store
) -> dict[str, Any]:
    """Disable an account; idempotent, but every accepted call is audited.

    The target's admin status is checked once up front and then re-read under
    the ``RuleService`` lock (the boundary promotion/removal use), so a target
    promoted after the fast check is still refused. The write itself is
    unconditional and its row is re-read inside the ``metadata.transaction``
    (gate2 G2-4); a repeat keeps the first ``disabled_at`` stamp.
    """
    db = request.app.state.metadata
    row = await users.get_by_id(db, user_id)
    if row is None:
        raise NotFound(f"user not found: {user_id}")
    if row.id == actor.id:
        raise AdminForbidden("you cannot disable your own account")
    target = AdminUser(row.id, row.login_key)
    ensure_can_disable_user(actor, target, await AdminChecker(store).is_admin(target))
    async with request.app.state.rules.lock:
        row = await users.get_by_id(db, user_id)
        if row is None:
            raise NotFound(f"user not found: {user_id}")
        target = AdminUser(row.id, row.login_key)
        target_is_admin = await AdminChecker(store).is_admin(target)
        ensure_can_disable_user(actor, target, target_is_admin)
        async with metadata.transaction(db):
            # Idempotent write, issued unconditionally, with the returned row
            # re-read inside the transaction: the outcome must not come from a
            # pre-transaction snapshot (gate2 G2-4).
            disabled = await users.set_disabled(db, row.id, True)
            assert disabled is not None
            row = disabled
            await audit.record(
                db,
                "admin",
                user_id=actor.id,
                detail={"action": "disable_user", "target_user_id": row.id},
            )
    return user_body(row, target_is_admin)


@router.post("/{user_id}/unbind")
async def unbind_user(
    user_id: int, request: Request, actor: Actor, store: Store
) -> dict[str, Any]:
    """Clear the bound OIDC subject so the next login binds the account again.

    For example the person was recreated in the IdP. An initial admin's subject
    is pinned in code and is never unbound; unbinding an admin account requires
    an initial-admin caller. Unbinding does not end the target's existing web
    sessions: they belong to the person who was bound. Idempotent, but every
    accepted call is audited. The ``oidc_sub = NULL`` update is unconditional and
    the returned row is re-read inside the ``metadata.transaction``, so a login
    that binds the account while the admin check runs is still cleared and the
    response reflects the transaction's state (gate2 G2-4).
    """
    db = request.app.state.metadata
    row = await users.get_by_id(db, user_id)
    if row is None:
        raise NotFound(f"user not found: {user_id}")
    target = AdminUser(row.id, row.login_key)
    ensure_can_unbind_user(actor, target, await AdminChecker(store).is_admin(target))
    async with request.app.state.rules.lock:
        row = await users.get_by_id(db, user_id)
        if row is None:
            raise NotFound(f"user not found: {user_id}")
        target = AdminUser(row.id, row.login_key)
        target_is_admin = await AdminChecker(store).is_admin(target)
        ensure_can_unbind_user(actor, target, target_is_admin)
        async with metadata.transaction(db):
            # Idempotent clear, issued unconditionally, with the returned row
            # re-read inside the transaction (gate2 G2-4).
            unbound = await users.unbind(db, row.id)
            assert unbound is not None
            row = unbound
            await audit.record(
                db,
                "admin",
                user_id=actor.id,
                detail={"action": "unbind_user", "target_user_id": row.id},
            )
    return user_body(row, target_is_admin)


@router.post("/{user_id}/enable")
async def enable_user(
    user_id: int, request: Request, actor: Actor, store: Store
) -> dict[str, Any]:
    """Clear disabled_at; idempotent, but every accepted call is audited."""
    db = request.app.state.metadata
    row = await users.get_by_id(db, user_id)
    if row is None:
        raise NotFound(f"user not found: {user_id}")
    async with metadata.transaction(db):
        # Idempotent write, issued unconditionally, with the returned row re-read
        # inside the transaction (gate2 G2-4).
        enabled = await users.set_disabled(db, row.id, False)
        assert enabled is not None
        row = enabled
        await audit.record(
            db,
            "admin",
            user_id=actor.id,
            detail={"action": "enable_user", "target_user_id": row.id},
        )
    return await user_view(row, AdminChecker(store))
