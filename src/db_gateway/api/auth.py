"""Fail-closed M1 identity boundary. Tests override ``current_user`` explicitly."""

from typing import Annotated

from fastapi import Depends, HTTPException, Request

from db_gateway.permissions import ids
from db_gateway.permissions.admin import INITIAL_ADMINS, AdminChecker, AdminForbidden, AdminUser
from db_gateway.permissions.store import PermissionStore, PermissionStoreUnavailable


async def current_user() -> AdminUser:
    raise HTTPException(status_code=401, detail="login not implemented, M1")


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
    if user.login_key not in INITIAL_ADMINS:
        raise AdminForbidden("only an initial admin may register connections")
    return user
