"""Browser login endpoints and the gateway's own session cookie."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Annotated, Any

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from db_gateway.api.auth import current_user
from db_gateway.auth.oidc import OidcClient, OidcIdentity, OidcRejected, OidcUnavailable
from db_gateway.auth.sessions import (
    SESSION_COOKIE,
    insert_session,
    lookup_session,
    mark_ended,
)
from db_gateway.auth.state import (
    LOGIN_COOKIE_PATH,
    LOGIN_STATE_TTL_S,
    LoginStateBrowserMismatch,
    code_challenge,
    consume_login_state,
    create_login_state,
    hash_browser_token,
    login_cookie_name,
    new_browser_token,
    new_code_verifier,
    new_nonce,
    new_state,
    safe_return_to,
)
from db_gateway.metadata import audit, transaction
from db_gateway.permissions.admin import AdminChecker, AdminUser, pinned_subject

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


def _metadata(request: Request) -> aiosqlite.Connection:
    db = getattr(request.app.state, "metadata", None)
    if db is None:
        raise HTTPException(status_code=503, detail="metadata database is unavailable")
    return db


def _oidc(request: Request) -> OidcClient:
    client = getattr(request.app.state, "oidc", None)
    if client is None or not client.ready:
        raise HTTPException(status_code=503, detail="OIDC login is not configured")
    return client


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client is not None else None


def _clear_login_cookie(response: Response, secure: bool, state: str) -> None:
    """Clear only the cookie belonging to this login transaction."""
    response.delete_cookie(
        login_cookie_name(state),
        path=LOGIN_COOKIE_PATH,
        secure=secure,
        httponly=True,
        samesite="lax",
    )


def _callback_error(
    request: Request, status_code: int, detail: str, *, state: str | None = None
) -> JSONResponse:
    """A short error response that discards only this transaction's login cookie."""
    response = JSONResponse(status_code=status_code, content={"detail": detail})
    if state is not None:
        _clear_login_cookie(response, request.app.state.settings.cookie_secure, state)
    return response


def _pin_instruction(login_key: str, subject: str) -> str:
    """The exact operator line to paste into permissions/admin.py."""
    return (
        "INITIAL_ADMINS = MappingProxyType({"
        f"{json.dumps(login_key)}: {json.dumps(subject)}"
        "})"
    )


@router.get("/auth/login")
async def login(
    request: Request,
    next_path: Annotated[str | None, Query(alias="next")] = None,
) -> RedirectResponse:
    """Create a single-use, browser-bound login state and redirect to the provider."""
    client = _oidc(request)
    db = _metadata(request)
    settings = request.app.state.settings
    state = new_state()
    nonce = new_nonce()
    verifier = new_code_verifier()
    try:
        url = await client.authorization_url(
            state=state, nonce=nonce, code_challenge=code_challenge(verifier)
        )
    except OidcUnavailable:
        raise HTTPException(status_code=503, detail="OIDC provider unavailable") from None
    browser_token = new_browser_token()
    await create_login_state(
        db,
        state=state,
        nonce=nonce,
        code_verifier=verifier,
        return_to=safe_return_to(next_path),
        browser_hash=hash_browser_token(browser_token),
    )
    response = RedirectResponse(url, status_code=302)
    response.set_cookie(
        login_cookie_name(state),
        browser_token,
        max_age=LOGIN_STATE_TTL_S,
        path=LOGIN_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/auth/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> Response:
    """Validate the browser binding, consume the state, and start a web session."""
    settings = request.app.state.settings
    if error is not None:
        return _callback_error(
            request, 400, "OIDC provider returned an error", state=state or None
        )
    if not code or not state:
        return _callback_error(request, 400, "missing code or state", state=state or None)
    client = getattr(request.app.state, "oidc", None)
    if client is None or not client.ready:
        return _callback_error(request, 503, "OIDC login is not configured", state=state)
    db = getattr(request.app.state, "metadata", None)
    if db is None:
        return _callback_error(request, 503, "metadata database is unavailable", state=state)
    browser_token = request.cookies.get(login_cookie_name(state))
    if browser_token is None:
        return _callback_error(request, 400, "invalid or expired login state", state=state)
    try:
        pending = await consume_login_state(
            db, state, browser_hash=hash_browser_token(browser_token)
        )
    except LoginStateBrowserMismatch:
        return _callback_error(request, 400, "invalid or expired login state", state=state)
    if pending is None:
        return _callback_error(request, 400, "invalid or expired login state", state=state)
    try:
        identity = await client.authenticate(
            code=code, code_verifier=pending.code_verifier, nonce=pending.nonce
        )
    except OidcRejected:
        return _callback_error(request, 400, "OIDC login failed", state=state)
    except OidcUnavailable:
        return _callback_error(request, 503, "OIDC provider unavailable", state=state)

    try:
        token = await _complete_login(db, identity, request)
    except HTTPException as exc:
        return _callback_error(request, exc.status_code, str(exc.detail), state=state)
    response = RedirectResponse(safe_return_to(pending.return_to), status_code=302)
    _clear_login_cookie(response, settings.cookie_secure, pending.state)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_ttl_s,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


async def _subject_bound_elsewhere(
    conn: aiosqlite.Connection, subject: str, *, exclude_id: int | None
) -> bool:
    sql = "SELECT 1 FROM users WHERE oidc_sub = ?"
    params: list[object] = [subject]
    if exclude_id is not None:
        sql += " AND id != ?"
        params.append(exclude_id)
    sql += " LIMIT 1"
    async with conn.execute(sql, params) as cursor:
        return await cursor.fetchone() is not None


async def _create_initial_admin(
    conn: aiosqlite.Connection, identity: OidcIdentity, pinned: str
) -> int:
    """Auto-create a pinned initial admin; the caller holds the transaction."""
    if not pinned:
        logger.warning(
            "initial admin %r has no pinned OIDC subject; login refused."
            " To allow this login, pin it in src/db_gateway/permissions/admin.py: %s",
            identity.login_key,
            _pin_instruction(identity.login_key, identity.subject),
        )
        raise HTTPException(status_code=403, detail="user is not allowed to log in")
    if identity.subject != pinned:
        logger.warning("OIDC subject mismatch for initial admin %s", identity.login_key)
        raise HTTPException(status_code=403, detail="user is not allowed to log in")
    if await _subject_bound_elsewhere(conn, identity.subject, exclude_id=None):
        logger.warning(
            "pinned OIDC subject for initial admin %s is already bound to another user",
            identity.login_key,
        )
        raise HTTPException(status_code=403, detail="user is not allowed to log in")
    cursor = await conn.execute(
        "INSERT INTO users (login_key, email, display_name, last_oidc_sub, oidc_sub) "
        "VALUES (?, ?, ?, ?, ?)",
        (identity.login_key, identity.email, identity.display_name, identity.subject, pinned),
    )
    assert cursor.lastrowid is not None
    return cursor.lastrowid


async def _check_subject_binding(
    conn: aiosqlite.Connection,
    identity: OidcIdentity,
    user_id: int,
    bound_sub: str | None,
    pinned: str | None,
) -> str:
    """Return the subject the account must be bound to, or refuse the login.

    Initial admins follow the code pin (an empty pin disables them); everyone
    else is bound on first login and must present the same subject afterwards.
    """
    if pinned is not None:
        if not pinned:
            logger.warning(
                "initial admin %r has no pinned OIDC subject; login refused."
                " To allow this login, pin it in src/db_gateway/permissions/admin.py: %s",
                identity.login_key,
                _pin_instruction(identity.login_key, identity.subject),
            )
            raise HTTPException(status_code=403, detail="user is not allowed to log in")
        if identity.subject != pinned:
            logger.warning("OIDC subject mismatch for user %s", user_id)
            raise HTTPException(status_code=403, detail="user is not allowed to log in")
        if await _subject_bound_elsewhere(conn, identity.subject, exclude_id=user_id):
            logger.warning(
                "pinned OIDC subject for user %s is already bound to another user", user_id
            )
            raise HTTPException(status_code=403, detail="user is not allowed to log in")
        return pinned
    if bound_sub is None:
        if await _subject_bound_elsewhere(conn, identity.subject, exclude_id=user_id):
            logger.warning("OIDC subject for user %s is already bound to another account", user_id)
            raise HTTPException(status_code=403, detail="user is not allowed to log in")
        return identity.subject
    if bound_sub != identity.subject:
        # Never replace an established binding: that would transfer the account.
        logger.warning("OIDC subject mismatch for user %s", user_id)
        raise HTTPException(status_code=403, detail="user is not allowed to log in")
    return bound_sub


async def _complete_login(
    db: aiosqlite.Connection, identity: OidcIdentity, request: Request
) -> str:
    """Map the identity to its bound user, then create an audited session."""
    settings = request.app.state.settings
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent")
    now = datetime.now(UTC)
    pinned = pinned_subject(identity.login_key)
    async with transaction(db):
        async with db.execute(
            "SELECT id, disabled_at, oidc_sub FROM users WHERE login_key = ?",
            (identity.login_key,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            if pinned is None:
                raise HTTPException(status_code=403, detail="user is not allowed to log in")
            user_id = await _create_initial_admin(db, identity, pinned)
            detail: dict[str, Any] = {
                "sub": identity.subject,
                "client_ip": client_ip,
                "created_user": True,
            }
        else:
            user_id, disabled_at, bound_sub = row
            if disabled_at is not None:
                raise HTTPException(status_code=403, detail="user is not allowed to log in")
            subject = await _check_subject_binding(db, identity, user_id, bound_sub, pinned)
            await db.execute(
                "UPDATE users SET last_oidc_sub = ?, oidc_sub = ?, "
                "email = CASE WHEN email IS NULL OR email = '' THEN ? ELSE email END, "
                "display_name = CASE WHEN display_name IS NULL OR display_name = '' "
                "THEN ? ELSE display_name END "
                "WHERE id = ?",
                (identity.subject, subject, identity.email, identity.display_name, user_id),
            )
            detail = {"sub": identity.subject, "client_ip": client_ip}

        token = await insert_session(
            db,
            user_id=user_id,
            ttl_s=settings.session_ttl_s,
            client_ip=client_ip,
            user_agent=user_agent,
            oidc_sid=identity.sid,
            now=now,
        )
        await audit.record(db, "login", user_id=user_id, detail=detail)
    return token


@router.post("/auth/logout", status_code=204)
async def logout(request: Request) -> Response:
    """End the cookie's session if it is live and always clear the cookie.

    The provider's end-session endpoint is deliberately not used: this gateway
    only owns its own web session, so logout is local and idempotent (204).
    """
    db = getattr(request.app.state, "metadata", None)
    token = request.cookies.get(SESSION_COOKIE)
    if db is not None and token is not None:
        session = await lookup_session(db, token)
        if session is not None and session.ended_at is None:
            async with transaction(db):
                ended = await mark_ended(db, session.token_hash, "logout")
                if ended:
                    await audit.record(
                        db,
                        "logout",
                        user_id=session.user_id,
                        detail={"client_ip": _client_ip(request)},
                    )
    settings = request.app.state.settings
    response = Response(status_code=204)
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/api/me")
async def me(
    request: Request, user: Annotated[AdminUser, Depends(current_user)]
) -> dict[str, Any]:
    db = _metadata(request)
    async with db.execute(
        "SELECT email, display_name FROM users WHERE id = ?", (user.id,)
    ) as cursor:
        row = await cursor.fetchone()
    is_initial_admin = pinned_subject(user.login_key) is not None
    is_admin: bool | None
    if is_initial_admin:
        is_admin = True
    else:
        store = getattr(request.app.state, "store", None)
        if store is None or not getattr(request.app.state, "store_ready", False):
            is_admin = None
        else:
            try:
                is_admin = await AdminChecker(store).is_admin(user)
            except Exception as exc:  # noqa: BLE001 - /api/me degrades instead of failing
                logger.warning("admin check failed for user %s: %s", user.id, type(exc).__name__)
                is_admin = None
    return {
        "id": user.id,
        "login_key": user.login_key,
        "email": row[0] if row is not None else None,
        "display_name": row[1] if row is not None else None,
        "is_admin": is_admin,
        "is_initial_admin": is_initial_admin,
    }
