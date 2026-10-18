"""Single-use pending OIDC login state bound to the starting browser.

The state, nonce and PKCE verifier live in SQLite rather than in a signed
cookie: the callback consumes the row atomically, so a replayed state finds
nothing and an abandoned login expires after ten minutes. A random login
transaction cookie set at ``/auth/login`` is stored as its SHA-256 and must
match on callback, so a callback URL stolen from another browser is refused
without consuming the legitimate browser's state.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import aiosqlite

from db_gateway.metadata import to_iso, transaction

LOGIN_STATE_TTL_S = 600
LOGIN_COOKIE_PREFIX = "dbgw_login_"
LOGIN_COOKIE_PATH = "/auth"


def login_cookie_name(state: str) -> str:
    """The cookie name for one login transaction, so tabs never overwrite each other."""
    return LOGIN_COOKIE_PREFIX + hashlib.sha256(state.encode("utf-8")).hexdigest()[:16]


class LoginStateBrowserMismatch(Exception):
    """The callback came from a different browser than the one that started it."""


@dataclass(frozen=True, slots=True)
class LoginState:
    state: str
    nonce: str
    code_verifier: str
    return_to: str
    expires_at: datetime


def new_browser_token() -> str:
    return secrets.token_urlsafe(32)


def hash_browser_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_state() -> str:
    return secrets.token_urlsafe(32)


def new_nonce() -> str:
    return secrets.token_urlsafe(32)


def new_code_verifier() -> str:
    return secrets.token_urlsafe(64)


def code_challenge(verifier: str) -> str:
    """S256 PKCE challenge: base64url(sha256(verifier)) without padding."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def safe_return_to(value: str | None) -> str:
    """Only accept a same-origin absolute path; anything suspicious becomes ``/``.

    A leading ``//`` is a scheme-relative URL, and a backslash or control
    character can be normalised by browsers into one. Queries and fragments
    are allowed because they stay on the gateway's origin.
    """
    if value is None or not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/"
    return value


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


async def create_login_state(
    conn: aiosqlite.Connection,
    *,
    state: str,
    nonce: str,
    code_verifier: str,
    return_to: str,
    browser_hash: str,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    expires_at = now + timedelta(seconds=LOGIN_STATE_TTL_S)
    async with transaction(conn):
        # Keep the table bounded even if callbacks never arrive.
        await conn.execute("DELETE FROM oidc_login_states WHERE expires_at <= ?", (to_iso(now),))
        await conn.execute(
            "INSERT INTO oidc_login_states "
            "(state, nonce, code_verifier, return_to, browser_hash, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                state,
                nonce,
                code_verifier,
                return_to,
                browser_hash,
                to_iso(now),
                to_iso(expires_at),
            ),
        )


async def consume_login_state(
    conn: aiosqlite.Connection,
    state: str,
    *,
    browser_hash: str,
    now: datetime | None = None,
) -> LoginState | None:
    """Verify the browser binding, then delete and return the state row.

    A missing or expired row returns None; a browser mismatch raises
    :class:`LoginStateBrowserMismatch` and leaves the row for the browser that
    started the login. The read and delete share one write transaction, so two
    callbacks can never consume the same state.
    """
    now = now or datetime.now(UTC)
    async with transaction(conn):
        async with conn.execute(
            "SELECT browser_hash, nonce, code_verifier, return_to, expires_at "
            "FROM oidc_login_states WHERE state = ?",
            (state,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        if not secrets.compare_digest(row[0], browser_hash):
            raise LoginStateBrowserMismatch("login state belongs to another browser")
        await conn.execute("DELETE FROM oidc_login_states WHERE state = ?", (state,))
    expires_at = _parse_timestamp(row[4])
    if expires_at <= now:
        return None
    return LoginState(
        state=state,
        nonce=row[1],
        code_verifier=row[2],
        return_to=row[3],
        expires_at=expires_at,
    )


__all__ = [
    "LOGIN_COOKIE_PATH",
    "LOGIN_COOKIE_PREFIX",
    "LOGIN_STATE_TTL_S",
    "LoginState",
    "LoginStateBrowserMismatch",
    "code_challenge",
    "consume_login_state",
    "create_login_state",
    "hash_browser_token",
    "login_cookie_name",
    "new_browser_token",
    "new_code_verifier",
    "new_nonce",
    "new_state",
    "safe_return_to",
]
