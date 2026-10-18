"""Server-side web session and pending-login-state storage."""

import sqlite3
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite
import pytest

from db_gateway.auth.sessions import (
    hash_token,
    insert_session,
    lookup_session,
    mark_ended,
    touch_session,
)
from db_gateway.auth.state import (
    LoginStateBrowserMismatch,
    code_challenge,
    consume_login_state,
    create_login_state,
    hash_browser_token,
    login_cookie_name,
    safe_return_to,
)
from db_gateway.metadata import connect, migrate, to_iso, transaction


@pytest.fixture
async def conn(tmp_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    db = await connect(tmp_path / "metadata.sqlite3")
    try:
        await migrate(db)
        yield db
    finally:
        await db.close()


def test_pkce_s256_matches_rfc_vector() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, "/"),
        ("/", "/"),
        ("/dashboard", "/dashboard"),
        ("/d?x=1#frag", "/d?x=1#frag"),
        ("https://evil.test/", "/"),
        ("//evil.test/", "/"),
        ("/\\evil.test", "/"),
        ("\\evil.test", "/"),
        ("evil.test", "/"),
        (" /dashboard", "/"),
        ("/d\tashboard", "/"),
        ("javascript:alert(1)", "/"),
    ],
)
def test_safe_return_to(value: str | None, expected: str) -> None:
    assert safe_return_to(value) == expected


def test_login_cookie_names_are_per_transaction() -> None:
    first = login_cookie_name("state-a")
    second = login_cookie_name("state-b")
    assert first != second
    assert first.startswith("dbgw_login_")
    assert len(first) == len("dbgw_login_") + 16
    assert login_cookie_name("state-a") == first


async def test_login_state_is_single_use_and_expires(conn: aiosqlite.Connection) -> None:
    now = datetime.now(UTC)
    browser_hash = hash_browser_token("browser-token")
    await create_login_state(
        conn,
        state="state-1",
        nonce="nonce-1",
        code_verifier="verifier-1",
        return_to="/next",
        browser_hash=browser_hash,
        now=now,
    )
    pending = await consume_login_state(
        conn, "state-1", browser_hash=browser_hash, now=now
    )
    assert pending is not None
    assert (pending.nonce, pending.code_verifier, pending.return_to) == (
        "nonce-1",
        "verifier-1",
        "/next",
    )
    assert (
        await consume_login_state(conn, "state-1", browser_hash=browser_hash, now=now) is None
    )

    old = now - timedelta(seconds=601)
    await create_login_state(
        conn,
        state="state-2",
        nonce="nonce-2",
        code_verifier="verifier-2",
        return_to="/",
        browser_hash=browser_hash,
        now=old,
    )
    assert (
        await consume_login_state(conn, "state-2", browser_hash=browser_hash, now=now) is None
    )
    async with conn.execute("SELECT count(*) FROM oidc_login_states") as cursor:
        assert await cursor.fetchone() == (0,)


async def test_login_state_browser_mismatch_does_not_consume(
    conn: aiosqlite.Connection,
) -> None:
    now = datetime.now(UTC)
    await create_login_state(
        conn,
        state="state-1",
        nonce="nonce-1",
        code_verifier="verifier-1",
        return_to="/",
        browser_hash=hash_browser_token("browser-a"),
        now=now,
    )
    with pytest.raises(LoginStateBrowserMismatch):
        await consume_login_state(
            conn, "state-1", browser_hash=hash_browser_token("browser-b"), now=now
        )
    async with conn.execute("SELECT count(*) FROM oidc_login_states") as cursor:
        assert await cursor.fetchone() == (1,)
    pending = await consume_login_state(
        conn, "state-1", browser_hash=hash_browser_token("browser-a"), now=now
    )
    assert pending is not None and pending.nonce == "nonce-1"


async def test_login_creation_purges_expired_rows(conn: aiosqlite.Connection) -> None:
    now = datetime.now(UTC)
    browser_hash = hash_browser_token("browser-token")
    await create_login_state(
        conn,
        state="old",
        nonce="old-nonce",
        code_verifier="old-verifier",
        return_to="/",
        browser_hash=browser_hash,
        now=now - timedelta(seconds=601),
    )
    await create_login_state(
        conn,
        state="new",
        nonce="new-nonce",
        code_verifier="new-verifier",
        return_to="/",
        browser_hash=browser_hash,
        now=now,
    )
    async with conn.execute("SELECT state FROM oidc_login_states") as cursor:
        assert await cursor.fetchall() == [("new",)]


async def test_session_token_is_only_stored_hashed(conn: aiosqlite.Connection) -> None:
    async with transaction(conn):
        await conn.execute("INSERT INTO users (id, login_key) VALUES (1, 'alice')")
    async with transaction(conn):
        token = await insert_session(
            conn,
            user_id=1,
            ttl_s=60,
            client_ip="127.0.0.1",
            user_agent="pytest",
            oidc_sid="sid-1",
        )
    async with conn.execute("SELECT token_hash, oidc_sid FROM web_sessions") as cursor:
        row = await cursor.fetchone()
    assert row == (hash_token(token), "sid-1")
    assert row is not None
    assert token not in "".join(str(value) for value in row)
    session = await lookup_session(conn, token)
    assert session is not None
    assert (session.user_id, session.login_key, session.email) == (1, "alice", None)
    assert session.ended_at is None and session.end_reason is None


async def test_unknown_session_is_not_found(conn: aiosqlite.Connection) -> None:
    assert await lookup_session(conn, "not-a-token") is None


async def test_mark_ended_is_idempotent_and_keeps_reason(
    conn: aiosqlite.Connection,
) -> None:
    async with transaction(conn):
        await conn.execute("INSERT INTO users (id, login_key) VALUES (1, 'alice')")
    async with transaction(conn):
        token = await insert_session(
            conn, user_id=1, ttl_s=60, client_ip=None, user_agent=None, oidc_sid=None
        )
    async with transaction(conn):
        assert await mark_ended(conn, hash_token(token), "logout")
        assert not await mark_ended(conn, hash_token(token), "idle")
    session = await lookup_session(conn, token)
    assert session is not None
    assert session.ended_at is not None and session.end_reason == "logout"


async def test_session_end_fields_must_agree(conn: aiosqlite.Connection) -> None:
    async with transaction(conn):
        await conn.execute("INSERT INTO users (id, login_key) VALUES (1, 'alice')")
    async with transaction(conn):
        await insert_session(
            conn, user_id=1, ttl_s=60, client_ip=None, user_agent=None, oidc_sid=None
        )
    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
        await conn.execute(
            "UPDATE web_sessions SET ended_at = ? WHERE user_id = 1",
            (to_iso(datetime.now(UTC)),),
        )


async def test_touch_updates_last_seen(conn: aiosqlite.Connection) -> None:
    async with transaction(conn):
        await conn.execute("INSERT INTO users (id, login_key) VALUES (1, 'alice')")
    async with transaction(conn):
        token = await insert_session(
            conn, user_id=1, ttl_s=60, client_ip=None, user_agent=None, oidc_sid=None
        )
    old = datetime(2026, 1, 1, tzinfo=UTC)
    async with transaction(conn):
        await touch_session(conn, hash_token(token), now=old)
    session = await lookup_session(conn, token)
    assert session is not None
    assert session.last_seen_at == old


async def test_raw_token_looking_hash_is_rejected(conn: aiosqlite.Connection) -> None:
    async with transaction(conn):
        await conn.execute("INSERT INTO users (id, login_key) VALUES (1, 'alice')")
    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
        await conn.execute(
            "INSERT INTO web_sessions (token_hash, user_id, expires_at) VALUES (?, 1, ?)",
            ("raw-session-token", to_iso(datetime.now(UTC) + timedelta(hours=1))),
        )


async def test_session_requires_an_existing_user(conn: aiosqlite.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        await conn.execute(
            "INSERT INTO web_sessions (token_hash, user_id, expires_at) VALUES (?, 999, ?)",
            (hash_token("token"), to_iso(datetime.now(UTC) + timedelta(hours=1))),
        )
