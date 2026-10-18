"""Identity boundary: the session cookie maps to an active gateway web session."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from db_gateway.auth.sessions import (
    SESSION_COOKIE,
    lookup_session,
    mark_ended,
    touch_session,
)
from db_gateway.metadata import transaction
from db_gateway.permissions import ids
from db_gateway.permissions.admin import (
    AdminChecker,
    AdminForbidden,
    AdminUser,
    pinned_subject,
)
from db_gateway.permissions.store import PermissionStore, PermissionStoreUnavailable


def login_required() -> HTTPException:
    return HTTPException(status_code=401, detail="authentication required")


async def current_user(request: Request) -> AdminUser:
    """Resolve the session cookie, enforcing idle/absolute expiry and disablement."""
    token = request.cookies.get(SESSION_COOKIE)
    db = getattr(request.app.state, "metadata", None)
    if token is None or db is None:
        raise login_required()

    session = await lookup_session(db, token)
    if session is None or session.ended_at is not None:
        raise login_required()

    now = datetime.now(UTC)
    idle_s = request.app.state.settings.session_idle_s
    reason: str | None = None
    if now >= session.expires_at:
        reason = "expired"
    elif session.disabled_at is not None:
        reason = "user_disabled"
    elif (now - session.last_seen_at).total_seconds() > idle_s:
        reason = "idle"
    if reason is not None:
        async with transaction(db):
            await mark_ended(db, session.token_hash, reason, now=now)
        raise login_required()

    # Persist every authenticated request: throttled timestamps would let the
    # idle check expire a session that was active inside the idle interval.
    async with transaction(db):
        await touch_session(db, session.token_hash, now=now)
    return AdminUser(id=session.user_id, login_key=session.login_key)


async def permission_store(request: Request) -> PermissionStore:
    store = request.app.state.store
    if store is None:
        raise PermissionStoreUnavailable("openfga_store_id must be configured")
    if not request.app.state.store_ready:
        async with request.app.state.store_model_lock:
            if not request.app.state.store_ready:
                await store.ensure_model()
                request.app.state.store_ready = True
    await store.read(ids.GATEWAY_MAIN, "admin")
    return store


async def require_admin(
    user: Annotated[AdminUser, Depends(current_user)],
    store: Annotated[PermissionStore, Depends(permission_store)],
) -> AdminUser:
    if not await AdminChecker(store).is_admin(user):
        raise AdminForbidden("only an admin may use the admin API")
    return user


async def require_initial_admin(
    user: Annotated[AdminUser, Depends(require_admin)],
) -> AdminUser:
    if pinned_subject(user.login_key) is None:
        raise AdminForbidden("only an initial admin may register connections")
    return user
