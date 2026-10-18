"""End-to-end OIDC login through create_app with an in-process fake provider."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import SplitResult, parse_qs, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from pydantic import SecretStr

from db_gateway.app import _parse_origin, create_app
from db_gateway.auth.sessions import SESSION_COOKIE, hash_token, insert_session
from db_gateway.auth.state import hash_browser_token, login_cookie_name
from db_gateway.metadata import to_iso, transaction
from db_gateway.permissions.store_memory import MemoryStore
from db_gateway.settings import Settings
from tests.fakes.oidc import FakeOidcProvider, challenge_for


@dataclass(frozen=True)
class Started:
    state: str
    nonce: str
    challenge: str
    location: SplitResult
    response: httpx.Response


def settings_for(
    tmp_path: Path, provider: FakeOidcProvider, **overrides: Any
) -> Settings:
    values: dict[str, Any] = {
        "metadata_db_path": tmp_path / "metadata.sqlite3",
        "oidc_issuer": provider.issuer,
        "oidc_client_id": provider.client_id,
        "oidc_client_secret": (
            SecretStr(provider.client_secret) if provider.client_secret is not None else None
        ),
        "oidc_redirect_uri": provider.redirect_uri,
        "cookie_secure": False,
    }
    values.update(overrides)
    return Settings(**values)


@asynccontextmanager
async def running(
    provider: FakeOidcProvider,
    tmp_path: Path,
    *,
    oidc_clock: Callable[[], float] | None = None,
    **overrides: Any,
) -> AsyncIterator[tuple[FastAPI, httpx.AsyncClient]]:
    app = create_app(
        settings_for(tmp_path, provider, **overrides),
        oidc_transport=provider.transport,
        oidc_clock=oidc_clock,
    )
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="https://gateway.test"
        ) as client:
            yield app, client


async def begin(client: httpx.AsyncClient, next_path: str | None = None) -> Started:
    response = await client.get(
        "/auth/login", params={"next": next_path} if next_path is not None else None
    )
    assert response.status_code == 302, response.text
    location = urlsplit(response.headers["location"])
    params = parse_qs(location.query)
    return Started(
        state=params["state"][0],
        nonce=params["nonce"][0],
        challenge=params["code_challenge"][0],
        location=location,
        response=response,
    )


async def finish(
    client: httpx.AsyncClient,
    provider: FakeOidcProvider,
    started: Started,
    **issue: Any,
) -> httpx.Response:
    code = provider.issue_code(
        nonce=started.nonce, code_challenge=started.challenge, **issue
    )
    return await client.get(
        "/auth/callback", params={"code": code, "state": started.state}
    )


async def concurrent_callbacks(
    app: FastAPI, provider: FakeOidcProvider, count: int, **issue: Any
) -> list[httpx.Response]:
    """Run independent browser logins and callbacks concurrently."""
    clients = [
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://gateway.test"
        )
        for _ in range(count)
    ]
    try:
        starts = [await begin(client) for client in clients]
        return await asyncio.gather(
            *(
                finish(client, provider, started, **issue)
                for client, started in zip(clients, starts, strict=True)
            )
        )
    finally:
        for client in clients:
            await client.aclose()


async def scalar(db: Any, query: str, params: tuple[Any, ...] = ()) -> Any:
    async with db.execute(query, params) as cursor:
        row = await cursor.fetchone()
    return row[0] if row is not None else None


async def insert_user(
    db: Any,
    login_key: str,
    *,
    email: str | None = None,
    display_name: str | None = None,
    disabled: bool = False,
    oidc_sub: str | None = None,
) -> int:
    async with transaction(db):
        cursor = await db.execute(
            "INSERT INTO users (login_key, email, display_name, disabled_at, oidc_sub) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                login_key,
                email,
                display_name,
                to_iso(datetime.now(UTC)) if disabled else None,
                oidc_sub,
            ),
        )
        assert cursor.lastrowid is not None
        return cursor.lastrowid


@pytest.fixture
def provider() -> FakeOidcProvider:
    return FakeOidcProvider()


@pytest.fixture(autouse=True)
def pinned_initial_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin andyjjrt to the fake provider's default subject for flow tests."""
    monkeypatch.setattr(
        "db_gateway.permissions.admin.INITIAL_ADMINS",
        MappingProxyType({"andyjjrt": "subject-1"}),
    )


async def test_happy_path_login_me_admin_logout(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        app.state.store = MemoryStore()
        app.state.store_ready = True
        started = await begin(client, next_path="/dashboard")
        assert started.location.netloc == "issuer.test"
        assert started.location.path == "/authorize"
        query = parse_qs(started.location.query)
        assert query["response_type"] == ["code"]
        assert query["client_id"] == [provider.client_id]
        assert query["redirect_uri"] == [provider.redirect_uri]
        assert query["scope"] == ["openid email profile"]
        assert query["code_challenge_method"] == ["S256"]
        assert query["state"] == [started.state]
        assert query["nonce"] == [started.nonce]
        login_attributes = [
            attribute.strip().lower()
            for attribute in started.response.headers["set-cookie"].split(";")
        ]
        assert "httponly" in login_attributes
        assert "samesite=lax" in login_attributes
        assert "path=/auth" in login_attributes
        assert "max-age=600" in login_attributes
        assert "secure" not in login_attributes
        login_cookie = login_cookie_name(started.state)
        browser_token = client.cookies.get(login_cookie)
        assert browser_token
        assert await scalar(
            app.state.metadata,
            "SELECT browser_hash FROM oidc_login_states WHERE state = ?",
            (started.state,),
        ) == hash_browser_token(browser_token)

        async with app.state.metadata.execute(
            "SELECT code_verifier, return_to FROM oidc_login_states WHERE state = ?",
            (started.state,),
        ) as cursor:
            verifier, return_to = await cursor.fetchone()
        assert return_to == "/dashboard"
        assert challenge_for(verifier) == started.challenge

        response = await finish(client, provider, started)
        assert response.status_code == 302
        assert response.headers["location"] == "/dashboard"
        set_cookies = response.headers.get_list("set-cookie")
        session_cookie = next(
            cookie for cookie in set_cookies if cookie.startswith(f"{SESSION_COOKIE}=")
        )
        cookie_attributes = [
            attribute.strip().lower() for attribute in session_cookie.split(";")
        ]
        assert "httponly" in cookie_attributes
        assert "samesite=lax" in cookie_attributes
        assert "path=/" in cookie_attributes
        assert "max-age=3600" in cookie_attributes
        assert "secure" not in cookie_attributes
        assert any(
            cookie.startswith(f"{login_cookie}=") and "max-age=0" in cookie.lower()
            for cookie in set_cookies
        )
        assert client.cookies.get(login_cookie) is None

        token = client.cookies.get(SESSION_COOKIE)
        assert token
        assert await scalar(
            app.state.metadata,
            "SELECT token_hash FROM web_sessions",
        ) == hash_token(token)
        assert await scalar(app.state.metadata, "SELECT oidc_sid FROM web_sessions") == "sid-1"
        assert token not in str(
            await scalar(app.state.metadata, "SELECT token_hash FROM web_sessions")
        )

        me = await client.get("/api/me")
        assert me.status_code == 200
        assert me.json() == {
            "id": 1,
            "login_key": "andyjjrt",
            "email": "andy@example.test",
            "display_name": "Andy",
            "is_admin": True,
            "is_initial_admin": True,
        }
        async with app.state.metadata.execute(
            "SELECT login_key, email, display_name, last_oidc_sub, oidc_sub FROM users"
        ) as cursor:
            assert await cursor.fetchone() == (
                "andyjjrt",
                "andy@example.test",
                "Andy",
                "subject-1",
                "subject-1",
            )

        admins = await client.get("/api/admin/admins")
        assert admins.status_code == 200, admins.text
        assert any(
            entry["login_key"] == "andyjjrt" and entry["initial"] for entry in admins.json()
        )

        logout = await client.post("/auth/logout")
        assert logout.status_code == 204
        assert not client.cookies.get(SESSION_COOKIE)
        assert (await client.get("/api/me")).status_code == 401
        assert await scalar(app.state.metadata, "SELECT end_reason FROM web_sessions") == "logout"
        assert (await client.post("/auth/logout")).status_code == 204

        async with app.state.metadata.execute(
            "SELECT kind, user_id, detail FROM audit_log ORDER BY id"
        ) as cursor:
            audit_rows = list(await cursor.fetchall())
        assert [row[0] for row in audit_rows] == ["login", "logout"]
        assert [row[1] for row in audit_rows] == [1, 1]
        login_detail = json.loads(audit_rows[0][2])
        assert login_detail["sub"] == "subject-1"
        assert login_detail["client_ip"] == "127.0.0.1"
        assert json.loads(audit_rows[1][2])["client_ip"] == "127.0.0.1"

        # Discovery and JWKS are cached across logins.
        assert provider.discovery_requests == 1
        assert provider.jwks_requests == 1


async def test_callback_is_bound_to_the_starting_browser(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client_a):
        started = await begin(client_a)
        login_cookie = login_cookie_name(started.state)
        code = provider.issue_code(
            nonce=started.nonce, code_challenge=started.challenge
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://gateway.test"
        ) as client_b:
            stolen = await client_b.get(
                "/auth/callback", params={"code": code, "state": started.state}
            )
            assert stolen.status_code == 400
            assert provider.token_requests == 0
            assert client_b.cookies.get(SESSION_COOKIE) is None
            assert client_b.cookies.get(login_cookie) is None
        assert await scalar(
            app.state.metadata,
            "SELECT count(*) FROM oidc_login_states WHERE state = ?",
            (started.state,),
        ) == 1
        legit = await client_a.get(
            "/auth/callback", params={"code": code, "state": started.state}
        )
        assert legit.status_code == 302
        assert client_a.cookies.get(SESSION_COOKIE)
        assert client_a.cookies.get(login_cookie) is None
        assert provider.token_requests == 1


@pytest.mark.parametrize("order", ["ab", "ba"])
async def test_overlapping_login_tabs_both_complete(
    provider: FakeOidcProvider, tmp_path: Path, order: str
) -> None:
    async with running(provider, tmp_path) as (app, client):
        first = await begin(client)
        second = await begin(client)
        tabs = {
            "a": (first, login_cookie_name(first.state)),
            "b": (second, login_cookie_name(second.state)),
        }
        assert tabs["a"][1] != tabs["b"][1]
        assert client.cookies.get(tabs["a"][1])
        assert client.cookies.get(tabs["b"][1])
        remaining = {"a", "b"}
        for label in order:
            tab, cookie_name = tabs[label]
            response = await finish(client, provider, tab)
            assert response.status_code == 302
            assert client.cookies.get(cookie_name) is None
            remaining.remove(label)
            for other in remaining:
                assert client.cookies.get(tabs[other][1])
        assert await scalar(app.state.metadata, "SELECT count(*) FROM web_sessions") == 2


async def test_stale_callback_does_not_break_newer_login(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        stale = await begin(client)
        fresh = await begin(client)
        stale_cookie = login_cookie_name(stale.state)
        fresh_cookie = login_cookie_name(fresh.state)
        # A bad code consumes the stale state and fails; only its cookie is cleared.
        failed = await client.get(
            "/auth/callback",
            params={"code": "not-the-issued-code", "state": stale.state},
        )
        assert failed.status_code == 400
        assert client.cookies.get(stale_cookie) is None
        assert client.cookies.get(fresh_cookie)
        completed = await finish(client, provider, fresh)
        assert completed.status_code == 302
        assert await scalar(app.state.metadata, "SELECT count(*) FROM web_sessions") == 1


async def test_secure_cookie_when_configured(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path, cookie_secure=True) as (_app, client):
        started = await begin(client)
        response = await finish(client, provider, started)
        session_cookie = next(
            cookie
            for cookie in response.headers.get_list("set-cookie")
            if cookie.startswith(f"{SESSION_COOKIE}=")
        )
        attributes = [attribute.strip().lower() for attribute in session_cookie.split(";")]
        assert "secure" in attributes


@pytest.mark.parametrize(
    "case",
    [
        "issuer",
        "audience",
        "expired",
        "iat",
        "nonce",
        "alg-none",
        "alg-hs256",
        "azp",
        "azp-single",
        "azp-missing",
        "azp-not-string",
        "azp-null-single",
        "azp-null-multi",
    ],
)
async def test_callback_rejects_bad_id_tokens(
    case: str, provider: FakeOidcProvider, tmp_path: Path
) -> None:
    now = int(time.time())
    issue: dict[str, Any] = {
        "issuer": {"claims": {"iss": "https://wrong.example"}},
        "audience": {"claims": {"aud": "another-client"}},
        "expired": {"claims": {"iat": now - 300, "exp": now - 120}},
        "iat": {"claims": {"iat": now + 120}},
        "nonce": {"claims": {"nonce": "wrong-nonce"}},
        "alg-none": {"algorithm": "none"},
        "alg-hs256": {"algorithm": "HS256"},
        "azp": {
            "claims": {
                "aud": [provider.client_id, "another-client"],
                "azp": "another-client",
            }
        },
        "azp-single": {"claims": {"azp": "another-client"}},
        "azp-missing": {"claims": {"aud": [provider.client_id, "another-client"]}},
        "azp-not-string": {"claims": {"azp": 42}},
        "azp-null-single": {"claims": {"azp": None}},
        "azp-null-multi": {
            "claims": {"aud": [provider.client_id, "another-client"], "azp": None}
        },
    }[case]
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        response = await finish(client, provider, started, **issue)
        assert response.status_code == 400, response.text
        assert (await client.get("/api/me")).status_code == 401
        assert await scalar(app.state.metadata, "SELECT count(*) FROM web_sessions") == 0
        assert await scalar(app.state.metadata, "SELECT count(*) FROM audit_log") == 0


async def test_login_claim_falls_back_to_userinfo(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        response = await finish(
            client,
            provider,
            started,
            claims={"preferred_username": None},
            userinfo={
                "sub": "subject-1",
                "preferred_username": "andyjjrt",
                "email": "andy@example.test",
                "name": "Andy",
            },
        )
        assert response.status_code == 302
        assert provider.userinfo_requests == 1
        assert await scalar(app.state.metadata, "SELECT login_key FROM users") == "andyjjrt"


async def test_userinfo_subject_mismatch_is_rejected(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (_app, client):
        started = await begin(client)
        response = await finish(
            client,
            provider,
            started,
            claims={"preferred_username": None},
            userinfo={"sub": "another-subject", "preferred_username": "andyjjrt"},
        )
        assert response.status_code == 400
        assert provider.userinfo_requests == 1


async def test_userinfo_without_login_claim_is_rejected(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (_app, client):
        started = await begin(client)
        response = await finish(
            client,
            provider,
            started,
            claims={"preferred_username": None},
            userinfo={"sub": "subject-1"},
        )
        assert response.status_code == 400


async def test_multiple_audiences_with_matching_azp_is_accepted(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (_app, client):
        started = await begin(client)
        response = await finish(
            client,
            provider,
            started,
            claims={
                "aud": [provider.client_id, "another-client"],
                "azp": provider.client_id,
            },
        )
        assert response.status_code == 302


async def test_single_audience_with_matching_azp_is_accepted(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (_app, client):
        started = await begin(client)
        response = await finish(client, provider, started, claims={"azp": provider.client_id})
        assert response.status_code == 302


async def test_discovery_issuer_mismatch_is_unavailable(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    provider.discovery_document["issuer"] = "https://different-issuer.test"
    async with running(provider, tmp_path) as (_app, client):
        response = await client.get("/auth/login")
        assert response.status_code == 503


async def test_callback_rejects_bad_signature(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    async with running(provider, tmp_path) as (_app, client):
        started = await begin(client)
        response = await finish(client, provider, started, signing_key=other_key)
        assert response.status_code == 400


async def test_unknown_kid_after_warm_cache_does_not_refetch_within_interval(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (_app, client):
        first = await begin(client)
        assert (await finish(client, provider, first)).status_code == 302
        assert provider.jwks_requests == 1

        second = await begin(client)
        response = await finish(client, provider, second, kid="retired-key")
        assert response.status_code == 400
        assert provider.jwks_requests == 1


async def test_unknown_kid_burst_shares_one_jwks_fetch(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, _client):
        clients = [
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://gateway.test"
            )
            for _ in range(5)
        ]
        try:
            starts = [await begin(client) for client in clients]
            responses = await asyncio.gather(
                *(
                    finish(client, provider, started, kid=f"missing-{index}")
                    for index, (client, started) in enumerate(
                        zip(clients, starts, strict=True)
                    )
                )
            )
        finally:
            for client in clients:
                await client.aclose()
        assert all(response.status_code == 400 for response in responses)
        assert provider.jwks_requests == 1
        assert provider.token_requests == 5


async def test_rotated_signing_key_is_picked_up_by_refetch(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path, oidc_jwks_min_refresh_s=0.0) as (_app, client):
        first = await begin(client)
        assert (await finish(client, provider, first)).status_code == 302
        assert provider.jwks_requests == 1

        rotated_key = provider.add_signing_key("rotated-key")
        second = await begin(client)
        response = await finish(
            client, provider, second, signing_key=rotated_key, kid="rotated-key"
        )
        assert response.status_code == 302
        assert provider.jwks_requests == 2


async def test_cold_jwks_http_failure_burst_fetches_once(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    provider.jwks_status = 503
    async with running(provider, tmp_path) as (app, _client):
        responses = await concurrent_callbacks(app, provider, 5)
        assert all(response.status_code == 503 for response in responses)
        assert provider.jwks_requests == 1
        assert provider.token_requests == 5


async def test_cold_invalid_jwks_burst_fetches_once(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    provider.jwks_keys = []
    async with running(provider, tmp_path) as (app, _client):
        responses = await concurrent_callbacks(app, provider, 5)
        assert all(response.status_code == 503 for response in responses)
        assert provider.jwks_requests == 1
        assert provider.token_requests == 5


async def test_jwks_recovers_after_injected_interval(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    clock = [0.0]
    provider.jwks_status = 503
    async with running(provider, tmp_path, oidc_clock=lambda: clock[0]) as (_app, client):
        started = await begin(client)
        assert (await finish(client, provider, started)).status_code == 503
        assert provider.jwks_requests == 1

        provider.jwks_status = 200
        clock[0] += 61.0
        started = await begin(client)
        assert (await finish(client, provider, started)).status_code == 302
        assert provider.jwks_requests == 2


async def test_public_client_uses_body_client_id(
    tmp_path: Path,
) -> None:
    provider = FakeOidcProvider(client_secret=None)
    async with running(provider, tmp_path) as (_app, client):
        started = await begin(client)
        assert (await finish(client, provider, started)).status_code == 302
        assert provider.token_requests == 1


async def test_confidential_client_with_wrong_secret_is_rejected(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(
        provider, tmp_path, oidc_client_secret=SecretStr("wrong-secret")
    ) as (_app, client):
        started = await begin(client)
        response = await finish(client, provider, started)
        assert response.status_code == 400


async def test_token_endpoint_failure_mapping(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (_app, client):
        started = await begin(client)
        response = await finish(client, provider, started, token_status=500)
        assert response.status_code == 503

    async with running(provider, tmp_path / "second") as (_app, client):
        started = await begin(client)
        response = await finish(client, provider, started, token_status=400)
        assert response.status_code == 400


async def test_unknown_login_state_is_rejected_without_exchange(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        code = provider.issue_code(
            nonce=started.nonce, code_challenge=started.challenge
        )
        response = await client.get(
            "/auth/callback", params={"code": code, "state": "unknown-state"}
        )
        assert response.status_code == 400
        assert provider.token_requests == 0
        assert await scalar(app.state.metadata, "SELECT count(*) FROM oidc_login_states") == 1
        # The failed callback clears only its own (unknown) transaction's
        # cookie; the real pending login in this browser is untouched.
        assert client.cookies.get(login_cookie_name(started.state))
        completed = await finish(client, provider, started)
        assert completed.status_code == 302


async def test_reused_login_state_is_rejected(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        login_cookie = login_cookie_name(started.state)
        browser_token = client.cookies.get(login_cookie)
        assert browser_token
        code = provider.issue_code(
            nonce=started.nonce, code_challenge=started.challenge
        )
        first = await client.get(
            "/auth/callback", params={"code": code, "state": started.state}
        )
        assert first.status_code == 302
        replay = await client.get(
            "/auth/callback",
            params={"code": code, "state": started.state},
            headers={"cookie": f"{login_cookie}={browser_token}"},
        )
        assert replay.status_code == 400
        assert provider.token_requests == 1
        assert await scalar(app.state.metadata, "SELECT count(*) FROM oidc_login_states") == 0


async def test_expired_login_state_is_rejected_before_exchange(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        code = provider.issue_code(
            nonce=started.nonce, code_challenge=started.challenge
        )
        async with transaction(app.state.metadata):
            await app.state.metadata.execute(
                "UPDATE oidc_login_states SET expires_at = ? WHERE state = ?",
                (to_iso(datetime.now(UTC) - timedelta(seconds=1)), started.state),
            )
        response = await client.get(
            "/auth/callback", params={"code": code, "state": started.state}
        )
        assert response.status_code == 400
        assert provider.token_requests == 0


async def test_callback_provider_and_parameter_errors(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (_app, client):
        assert (
            await client.get("/auth/callback", params={"error": "access_denied"})
        ).status_code == 400
        assert (await client.get("/auth/callback")).status_code == 400
        assert (
            await client.get("/auth/callback", params={"code": "only-code"})
        ).status_code == 400


@pytest.mark.parametrize(
    "next_path, expected",
    [
        ("https://evil.test/", "/"),
        ("//evil.test/", "/"),
        ("/\\evil.test", "/"),
        ("evil.test", "/"),
        ("/dashboard", "/dashboard"),
        ("/items?page=2#top", "/items?page=2#top"),
    ],
)
async def test_open_redirect_next_is_confined(
    next_path: str, expected: str, provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client, next_path=next_path)
        assert await scalar(
            app.state.metadata,
            "SELECT return_to FROM oidc_login_states WHERE state = ?",
            (started.state,),
        ) == expected
        response = await finish(client, provider, started)
        assert response.status_code == 302
        assert response.headers["location"] == expected


async def test_unknown_non_initial_user_is_forbidden(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        response = await finish(
            client, provider, started, claims={"preferred_username": "mallory"}
        )
        assert response.status_code == 403
        assert await scalar(app.state.metadata, "SELECT count(*) FROM users") == 0
        assert await scalar(app.state.metadata, "SELECT count(*) FROM web_sessions") == 0


async def test_disabled_user_is_forbidden_at_login(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        await insert_user(app.state.metadata, "bob", disabled=True)
        started = await begin(client)
        response = await finish(
            client, provider, started, claims={"preferred_username": "bob"}
        )
        assert response.status_code == 403
        assert await scalar(app.state.metadata, "SELECT count(*) FROM web_sessions") == 0


async def test_existing_non_initial_user_is_accepted_and_profile_filled(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        await insert_user(app.state.metadata, "bob")
        started = await begin(client)
        response = await finish(
            client,
            provider,
            started,
            claims={
                "preferred_username": "bob",
                "sub": "bob-subject",
                "email": "bob@example.test",
                "name": "Bob",
            },
        )
        assert response.status_code == 302
        async with app.state.metadata.execute(
            "SELECT email, display_name, last_oidc_sub, oidc_sub FROM users "
            "WHERE login_key = 'bob'"
        ) as cursor:
            assert await cursor.fetchone() == (
                "bob@example.test",
                "Bob",
                "bob-subject",
                "bob-subject",
            )
        me = await client.get("/api/me")
        assert me.status_code == 200
        assert me.json()["is_admin"] is None
        assert me.json()["is_initial_admin"] is False


async def test_first_login_binds_and_same_subject_can_return(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        await insert_user(app.state.metadata, "bob")
        first = await begin(client)
        assert (
            await finish(
                client,
                provider,
                first,
                claims={"preferred_username": "bob", "sub": "bob-subject"},
            )
        ).status_code == 302
        second = await begin(client)
        assert (
            await finish(
                client,
                provider,
                second,
                claims={"preferred_username": "bob", "sub": "bob-subject"},
            )
        ).status_code == 302
        async with app.state.metadata.execute(
            "SELECT oidc_sub, last_oidc_sub FROM users WHERE login_key = 'bob'"
        ) as cursor:
            assert await cursor.fetchone() == ("bob-subject", "bob-subject")
        assert await scalar(app.state.metadata, "SELECT count(*) FROM web_sessions") == 2


async def test_bound_subject_mismatch_is_forbidden(
    provider: FakeOidcProvider,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with running(provider, tmp_path) as (app, client):
        user_id = await insert_user(app.state.metadata, "bob", oidc_sub="bob-subject")
        started = await begin(client)
        response = await finish(
            client,
            provider,
            started,
            claims={"preferred_username": "bob", "sub": "attacker-subject"},
        )
        assert response.status_code == 403
        assert "subject mismatch for user" in caplog.text
        assert "attacker-subject" not in caplog.text
        assert "bob-subject" not in caplog.text
        async with app.state.metadata.execute(
            "SELECT oidc_sub, last_oidc_sub FROM users WHERE id = ?", (user_id,)
        ) as cursor:
            assert await cursor.fetchone() == ("bob-subject", None)
        assert await scalar(app.state.metadata, "SELECT count(*) FROM web_sessions") == 0
        assert await scalar(app.state.metadata, "SELECT count(*) FROM audit_log") == 0


async def test_subject_already_bound_to_another_user_is_forbidden(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        await insert_user(app.state.metadata, "bob", oidc_sub="shared-subject")
        carol_id = await insert_user(app.state.metadata, "carol")
        started = await begin(client)
        response = await finish(
            client,
            provider,
            started,
            claims={"preferred_username": "carol", "sub": "shared-subject"},
        )
        assert response.status_code == 403
        async with app.state.metadata.execute(
            "SELECT oidc_sub FROM users WHERE id = ?", (carol_id,)
        ) as cursor:
            assert await cursor.fetchone() == (None,)


async def test_initial_admin_wrong_subject_on_auto_create_is_forbidden(
    provider: FakeOidcProvider,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        response = await finish(
            client, provider, started, claims={"sub": "attacker-subject"}
        )
        assert response.status_code == 403
        assert "initial admin" in caplog.text
        assert "attacker-subject" not in caplog.text
        assert "attacker-subject" not in response.text
        assert await scalar(app.state.metadata, "SELECT count(*) FROM users") == 0
        assert await scalar(app.state.metadata, "SELECT count(*) FROM web_sessions") == 0


async def test_initial_admin_wrong_subject_on_existing_row_is_forbidden(
    provider: FakeOidcProvider,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with running(provider, tmp_path) as (app, client):
        user_id = await insert_user(app.state.metadata, "andyjjrt")
        started = await begin(client)
        response = await finish(
            client, provider, started, claims={"sub": "attacker-subject"}
        )
        assert response.status_code == 403
        assert "subject mismatch" in caplog.text
        assert "attacker-subject" not in caplog.text
        assert "INITIAL_ADMINS = MappingProxyType" not in caplog.text
        assert "attacker-subject" not in response.text
        async with app.state.metadata.execute(
            "SELECT oidc_sub, last_oidc_sub FROM users WHERE id = ?", (user_id,)
        ) as cursor:
            assert await cursor.fetchone() == (None, None)
        assert await scalar(app.state.metadata, "SELECT count(*) FROM web_sessions") == 0


async def test_unpinned_initial_admin_cannot_log_in(
    provider: FakeOidcProvider,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(
        "db_gateway.permissions.admin.INITIAL_ADMINS",
        MappingProxyType({"andyjjrt": ""}),
    )
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        response = await finish(client, provider, started)
        assert response.status_code == 403
        assert "subject-1" in caplog.text
        assert (
            'INITIAL_ADMINS = MappingProxyType({"andyjjrt": "subject-1"})'
            in caplog.text
        )
        assert "subject-1" not in response.text
        assert await scalar(app.state.metadata, "SELECT count(*) FROM users") == 0


async def test_unpinned_initial_admin_existing_row_warns_with_subject(
    provider: FakeOidcProvider,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(
        "db_gateway.permissions.admin.INITIAL_ADMINS",
        MappingProxyType({"andyjjrt": ""}),
    )
    async with running(provider, tmp_path) as (app, client):
        user_id = await insert_user(app.state.metadata, "andyjjrt")
        started = await begin(client)
        response = await finish(client, provider, started)
        assert response.status_code == 403
        assert (
            'INITIAL_ADMINS = MappingProxyType({"andyjjrt": "subject-1"})'
            in caplog.text
        )
        assert "subject-1" not in response.text
        async with app.state.metadata.execute(
            "SELECT oidc_sub FROM users WHERE id = ?", (user_id,)
        ) as cursor:
            assert await cursor.fetchone() == (None,)


async def test_pinned_subject_wins_over_an_old_binding(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        user_id = await insert_user(
            app.state.metadata, "andyjjrt", oidc_sub="stale-subject"
        )
        started = await begin(client)
        response = await finish(client, provider, started)
        assert response.status_code == 302
        async with app.state.metadata.execute(
            "SELECT oidc_sub, last_oidc_sub FROM users WHERE id = ?", (user_id,)
        ) as cursor:
            assert await cursor.fetchone() == ("subject-1", "subject-1")


async def test_pinned_subject_bound_to_another_user_is_forbidden(
    provider: FakeOidcProvider,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with running(provider, tmp_path) as (app, client):
        await insert_user(app.state.metadata, "mallory", oidc_sub="subject-1")
        started = await begin(client)
        response = await finish(client, provider, started)
        assert response.status_code == 403
        assert "already bound to another user" in caplog.text
        assert await scalar(
            app.state.metadata, "SELECT count(*) FROM users WHERE login_key = 'andyjjrt'"
        ) == 0


async def test_idle_expiry_ends_the_session(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path, session_idle_s=300) as (app, client):
        started = await begin(client)
        assert (await finish(client, provider, started)).status_code == 302
        token = client.cookies.get(SESSION_COOKIE)
        assert token
        async with transaction(app.state.metadata):
            await app.state.metadata.execute(
                "UPDATE web_sessions SET last_seen_at = ? WHERE token_hash = ?",
                (
                    to_iso(datetime.now(UTC) - timedelta(seconds=301)),
                    hash_token(token),
                ),
            )
        assert (await client.get("/api/me")).status_code == 401
        assert await scalar(app.state.metadata, "SELECT end_reason FROM web_sessions") == "idle"


async def test_absolute_expiry_ends_the_session(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        assert (await finish(client, provider, started)).status_code == 302
        token = client.cookies.get(SESSION_COOKIE)
        assert token
        async with transaction(app.state.metadata):
            await app.state.metadata.execute(
                "UPDATE web_sessions SET expires_at = ? WHERE token_hash = ?",
                (
                    to_iso(datetime.now(UTC) - timedelta(seconds=1)),
                    hash_token(token),
                ),
            )
        assert (await client.get("/api/me")).status_code == 401
        assert await scalar(app.state.metadata, "SELECT end_reason FROM web_sessions") == "expired"


async def test_disabled_account_ends_the_session(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        await insert_user(app.state.metadata, "bob")
        started = await begin(client)
        assert (
            await finish(
                client, provider, started, claims={"preferred_username": "bob"}
            )
        ).status_code == 302
        async with transaction(app.state.metadata):
            await app.state.metadata.execute(
                "UPDATE users SET disabled_at = ? WHERE login_key = 'bob'",
                (to_iso(datetime.now(UTC)),),
            )
        assert (await client.get("/api/me")).status_code == 401
        assert (
            await scalar(app.state.metadata, "SELECT end_reason FROM web_sessions")
            == "user_disabled"
        )


async def test_last_seen_updates_on_every_request(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        started = await begin(client)
        assert (await finish(client, provider, started)).status_code == 302
        token = client.cookies.get(SESSION_COOKIE)
        assert token
        digest = hash_token(token)
        old = to_iso(datetime.now(UTC) - timedelta(seconds=1))
        async with transaction(app.state.metadata):
            await app.state.metadata.execute(
                "UPDATE web_sessions SET last_seen_at = ? WHERE token_hash = ?",
                (old, digest),
            )
        assert (await client.get("/api/me")).status_code == 200
        assert await scalar(
            app.state.metadata,
            "SELECT last_seen_at FROM web_sessions WHERE token_hash = ?",
            (digest,),
        ) > old


@pytest.mark.parametrize(
    "idle_s, active_offset, expired_offset",
    [(10, 5, 15), (300, 295, 305)],
)
async def test_idle_boundary_uses_the_last_request_time(
    provider: FakeOidcProvider,
    tmp_path: Path,
    idle_s: int,
    active_offset: int,
    expired_offset: int,
) -> None:
    async with running(provider, tmp_path, session_idle_s=idle_s) as (app, client):
        started = await begin(client)
        assert (await finish(client, provider, started)).status_code == 302
        token = client.cookies.get(SESSION_COOKIE)
        assert token
        digest = hash_token(token)

        # A request inside the old 30-second throttle window must still refresh
        # last_seen_at, otherwise the next check can expire the session early.
        active = to_iso(datetime.now(UTC) - timedelta(seconds=active_offset))
        async with transaction(app.state.metadata):
            await app.state.metadata.execute(
                "UPDATE web_sessions SET last_seen_at = ? WHERE token_hash = ?",
                (active, digest),
            )
        assert (await client.get("/api/me")).status_code == 200
        refreshed = await scalar(
            app.state.metadata,
            "SELECT last_seen_at FROM web_sessions WHERE token_hash = ?",
            (digest,),
        )
        assert refreshed > active

        expired = to_iso(datetime.now(UTC) - timedelta(seconds=expired_offset))
        async with transaction(app.state.metadata):
            await app.state.metadata.execute(
                "UPDATE web_sessions SET last_seen_at = ? WHERE token_hash = ?",
                (expired, digest),
            )
        assert (await client.get("/api/me")).status_code == 401
        assert await scalar(app.state.metadata, "SELECT end_reason FROM web_sessions") == "idle"


async def test_me_returns_null_admin_when_openfga_is_unavailable(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (app, client):
        user_id = await insert_user(app.state.metadata, "bob")
        async with transaction(app.state.metadata):
            token = await insert_session(
                app.state.metadata,
                user_id=user_id,
                ttl_s=3600,
                client_ip=None,
                user_agent=None,
                oidc_sid=None,
            )
        response = await client.get(
            "/api/me", headers={"cookie": f"{SESSION_COOKIE}={token}"}
        )
        assert response.status_code == 200
        assert response.json()["is_admin"] is None
        assert response.json()["is_initial_admin"] is False


async def test_cross_origin_unsafe_requests_are_rejected(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path) as (_app, client):
        rejected = await client.post(
            "/auth/logout", headers={"Origin": "https://evil.test"}
        )
        assert rejected.status_code == 403
        accepted = await client.post(
            "/auth/logout", headers={"Origin": "https://gateway.test"}
        )
        assert accepted.status_code == 204
        assert (await client.post("/auth/logout")).status_code == 204
        api_rejected = await client.post(
            "/api/admin/groups",
            json={"name": "analysts"},
            headers={"Origin": "https://evil.test"},
        )
        assert api_rejected.status_code == 403


@pytest.mark.parametrize(
    "redirect_uri, origin, expected",
    [
        ("https://gateway.test:443/auth/callback", "https://gateway.test", 204),
        ("http://gateway.test:80/auth/callback", "http://gateway.test", 204),
        ("https://gateway.test/auth/callback", "HTTPS://GATEWAY.TEST:443", 204),
        ("https://gateway.test:8443/auth/callback", "https://gateway.test", 403),
        ("https://gateway.test/auth/callback", "https://gateway.test:8443", 403),
        ("https://gateway.test/auth/callback", "not-an-origin", 403),
        ("https://gateway.test/auth/callback", "null", 403),
        ("https://gateway.test/auth/callback", "https://gateway.test/evil", 403),
        ("https://gateway.test/auth/callback", "https://gateway.test:", 403),
        ("https://gateway.test/auth/callback", " https://gateway.test", 403),
        ("https://gateway.test/auth/callback", "https://gate\tway.test", 403),
    ],
)
async def test_origin_comparison_is_normalized(
    provider: FakeOidcProvider,
    tmp_path: Path,
    redirect_uri: str,
    origin: str,
    expected: int,
) -> None:
    async with running(
        provider, tmp_path, oidc_redirect_uri=redirect_uri
    ) as (_app, client):
        response = await client.post("/auth/logout", headers={"Origin": origin})
        assert response.status_code == expected


@pytest.mark.parametrize(
    "value",
    [
        " https://gateway.test",
        "https://gateway.test ",
        "https://gate\tway.test",
        "https://gateway.test\n",
        "https://gateway.test:",
        "https://[::1]:",
        "https://gateway.test:\t",
    ],
)
def test_parse_origin_rejects_raw_whitespace_and_empty_port(value: str) -> None:
    assert _parse_origin(value, allow_path=False) is None


@pytest.mark.parametrize(
    "value, expected",
    [
        ("https://gateway.test", ("https", "gateway.test", 443)),
        ("https://gateway.test:443", ("https", "gateway.test", 443)),
        ("HTTPS://GATEWAY.TEST:443", ("https", "gateway.test", 443)),
        ("http://gateway.test", ("http", "gateway.test", 80)),
        ("http://gateway.test:80", ("http", "gateway.test", 80)),
        ("https://[::1]:443", ("https", "::1", 443)),
    ],
)
def test_parse_origin_normalizes_valid_origins(
    value: str, expected: tuple[str, str, int]
) -> None:
    assert _parse_origin(value, allow_path=False) == expected


async def test_present_origin_without_redirect_uri_is_rejected(
    provider: FakeOidcProvider, tmp_path: Path
) -> None:
    async with running(provider, tmp_path, oidc_redirect_uri=None) as (_app, client):
        response = await client.post(
            "/auth/logout", headers={"Origin": "https://gateway.test"}
        )
        assert response.status_code == 403


async def test_login_without_oidc_configuration_is_503(tmp_path: Path) -> None:
    app = create_app(Settings(metadata_db_path=tmp_path / "metadata.sqlite3"))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://gateway.test"
        ) as client:
            assert (await client.get("/auth/login")).status_code == 503
            assert (await client.get("/api/me")).status_code == 401
            assert (await client.get("/api/admin/groups")).status_code == 401
