"""Server-side gateway web sessions.

The browser holds a random token; SQLite stores only its SHA-256. A session
ends on logout, absolute expiry, idle expiry or account disablement, and the
row keeps the reason so operators can audit why a session stopped.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import aiosqlite

from db_gateway.metadata import to_iso

SESSION_COOKIE = "dbgw_session"
_MAX_USER_AGENT_LEN = 1024


@dataclass(frozen=True, slots=True)
class WebSession:
    token_hash: str
    user_id: int
    login_key: str
    email: str | None
    display_name: str | None
    last_seen_at: datetime
    expires_at: datetime
    ended_at: datetime | None
    end_reason: str | None
    disabled_at: datetime | None


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


async def insert_session(
    conn: aiosqlite.Connection,
    *,
    user_id: int,
    ttl_s: int,
    client_ip: str | None,
    user_agent: str | None,
    oidc_sid: str | None,
    now: datetime | None = None,
) -> str:
    """Create a session and return the raw token; callers must be in a transaction."""
    token = new_session_token()
    now = now or datetime.now(UTC)
    expires_at = now + timedelta(seconds=ttl_s)
    if user_agent is not None:
        user_agent = user_agent[:_MAX_USER_AGENT_LEN]
    await conn.execute(
        "INSERT INTO web_sessions "
        "(token_hash, user_id, last_seen_at, expires_at, client_ip, user_agent, oidc_sid, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            hash_token(token),
            user_id,
            to_iso(now),
            to_iso(expires_at),
            client_ip,
            user_agent,
            oidc_sid,
            to_iso(now),
        ),
    )
    return token


async def lookup_session(conn: aiosqlite.Connection, token: str) -> WebSession | None:
    return await lookup_session_by_hash(conn, hash_token(token))


async def lookup_session_by_hash(
    conn: aiosqlite.Connection, token_hash: str
) -> WebSession | None:
    async with conn.execute(
        "SELECT s.token_hash, s.user_id, u.login_key, u.email, u.display_name, "
        "s.last_seen_at, s.expires_at, s.ended_at, s.end_reason, u.disabled_at "
        "FROM web_sessions AS s JOIN users AS u ON u.id = s.user_id "
        "WHERE s.token_hash = ?",
        (token_hash,),
    ) as cursor:
        row = await cursor.fetchone()
    if row is None:
        return None
    return WebSession(
        token_hash=row[0],
        user_id=row[1],
        login_key=row[2],
        email=row[3],
        display_name=row[4],
        last_seen_at=_parse_timestamp(row[5]),
        expires_at=_parse_timestamp(row[6]),
        ended_at=_parse_timestamp(row[7]) if row[7] is not None else None,
        end_reason=row[8],
        disabled_at=_parse_timestamp(row[9]) if row[9] is not None else None,
    )


async def mark_ended(
    conn: aiosqlite.Connection,
    token_hash: str,
    reason: str,
    *,
    now: datetime | None = None,
) -> bool:
    """End a live session once; returns True when this call ended it."""
    now = now or datetime.now(UTC)
    cursor = await conn.execute(
        "UPDATE web_sessions SET ended_at = ?, end_reason = ? "
        "WHERE token_hash = ? AND ended_at IS NULL",
        (to_iso(now), reason, token_hash),
    )
    return cursor.rowcount == 1


async def touch_session(
    conn: aiosqlite.Connection, token_hash: str, *, now: datetime | None = None
) -> None:
    now = now or datetime.now(UTC)
    await conn.execute(
        "UPDATE web_sessions SET last_seen_at = ? WHERE token_hash = ? AND ended_at IS NULL",
        (to_iso(now), token_hash),
    )
