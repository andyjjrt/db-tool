"""Admin users API: every endpoint, rule and audit row, without external services.

The app is the real :func:`db_gateway.app.create_app` (its exception handlers
map the typed errors and includes ``db_gateway.api.admin_users.router``), with
a real metadata SQLite database. Only the identity boundary (``current_user``)
and the permission store are overridden; the store is the deterministic
in-memory implementation that ``tests/unit/test_store_contract.py`` holds to
the same contract as OpenFGA. The module still lives under tests/integration,
so conftest marks it and skips it when docker compose is down.
"""

import asyncio
import json
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from db_gateway import metadata
from db_gateway.api.auth import current_user, permission_store
from db_gateway.app import create_app
from db_gateway.permissions.admin import INITIAL_ADMINS, AdminUser
from db_gateway.permissions.rules import RuleService
from db_gateway.permissions.store import Tuple
from db_gateway.permissions.store_memory import MemoryStore
from db_gateway.permissions.types import PgOp
from db_gateway.settings import Settings

# The single initial admin of INITIAL_ADMINS; seeded users 2-4 are not initial.
INITIAL = sorted(INITIAL_ADMINS)[0]


class UnusedExecutor:
    """RuleService needs an executor; these tests never touch a target database."""

    async def apply(self, connection: str, ops: Sequence[PgOp]) -> Sequence[PgOp]:
        raise AssertionError("the admin users routes must not run target ops")


class UnusedStats:
    async def distinct_count(
        self, connection: str, schema: str, table: str, column: str, limit: int
    ) -> int:
        raise AssertionError("the admin users routes must not count partitions")


@dataclass
class UsersWorld:
    app: FastAPI
    client: httpx.AsyncClient
    store: MemoryStore

    async def request(
        self, method: str, path: str, body: dict[str, Any] | None = None, code: int = 200
    ) -> httpx.Response:
        response = await self.client.request(method, "/api/admin/users" + path, json=body)
        assert response.status_code == code, response.text
        return response

    def act_as(self, user_id: int, login_key: str) -> None:
        self.app.dependency_overrides[current_user] = lambda: AdminUser(user_id, login_key)

    async def bind(self, user_id: int, oidc_sub: str) -> None:
        """Simulate the login flow's subject binding for one user."""
        async with metadata.transaction(self.app.state.metadata):
            await self.app.state.metadata.execute(
                "UPDATE users SET oidc_sub = ? WHERE id = ?", (oidc_sub, user_id)
            )

    async def audit_rows(self) -> list[dict[str, Any]]:
        async with self.app.state.metadata.execute(
            "SELECT kind, user_id, detail FROM audit_log ORDER BY id"
        ) as cur:
            return [
                {"kind": row[0], "user_id": row[1], "detail": json.loads(row[2])}
                for row in await cur.fetchall()
            ]


@pytest_asyncio.fixture
async def world(tmp_path: Path) -> AsyncIterator[UsersWorld]:
    settings = Settings(metadata_db_path=tmp_path / "metadata.sqlite3", openfga_store_id=None)
    app = create_app(settings)
    store = MemoryStore()
    app.dependency_overrides[permission_store] = lambda: store
    app.dependency_overrides[current_user] = lambda: AdminUser(1, INITIAL)
    async with app.router.lifespan_context(app):
        async with metadata.transaction(app.state.metadata):
            for user_id, login_key in ((1, INITIAL), (2, "helper"), (3, "plain"), (4, "other")):
                await app.state.metadata.execute(
                    "INSERT INTO users (id, login_key) VALUES (?, ?)", (user_id, login_key)
                )
        # helper and other are ordinary admins; plain is not.
        await store.write(
            writes=[
                Tuple("user:2", "admin", "gateway:main"),
                Tuple("user:4", "admin", "gateway:main"),
            ]
        )
        # The real app builds a RuleService only when OpenFGA is configured; the
        # disable and unbind routes hold its lock (gate M3), so wire one here.
        app.state.rules = RuleService(app.state.metadata, store, UnusedExecutor(), UnusedStats())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield UsersWorld(app, client, store)


ROUTES = [
    ("GET", ""),
    ("POST", ""),
    ("GET", "/2"),
    ("PATCH", "/2"),
    ("POST", "/2/disable"),
    ("POST", "/2/unbind"),
    ("POST", "/2/enable"),
]


async def test_every_endpoint_requires_identity_and_admin(world: UsersWorld) -> None:
    world.app.dependency_overrides.pop(current_user)
    for method, path in ROUTES:
        await world.request(method, path, code=401)
    world.act_as(3, "plain")
    for method, path in ROUTES:
        await world.request(method, path, code=403)


async def test_create_list_get_and_disabled_filter(world: UsersWorld) -> None:
    body = {"login_key": "alice", "email": "a@example.com", "display_name": "Alice"}
    created = (await world.request("POST", "", body, 201)).json()
    assert created == {
        "id": 5,
        "login_key": "alice",
        "email": "a@example.com",
        "display_name": "Alice",
        "disabled_at": None,
        "oidc_bound": False,
        "is_admin": False,
        "is_initial_admin": False,
        "created_at": created["created_at"],
    }
    assert created["created_at"].endswith("Z")
    assert (await world.request("GET", "/5")).json() == created
    await world.request("GET", "/4040", code=404)
    await world.request("GET", "/not-a-number", code=422)

    listed = (await world.request("GET", "")).json()
    assert [row["login_key"] for row in listed] == ["alice", INITIAL, "helper", "other", "plain"]
    assert {row["login_key"]: (row["is_admin"], row["is_initial_admin"]) for row in listed} == {
        "alice": (False, False),
        INITIAL: (True, True),
        "helper": (True, False),
        "other": (True, False),
        "plain": (False, False),
    }

    # Any admin may disable a plain user; the list still shows them by default.
    await world.request("POST", "/3/disable")
    assert [row["login_key"] for row in (await world.request("GET", "")).json()] == [
        "alice",
        INITIAL,
        "helper",
        "other",
        "plain",
    ]
    enabled_only = (await world.request("GET", "?include_disabled=false")).json()
    assert [row["login_key"] for row in enabled_only] == ["alice", INITIAL, "helper", "other"]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"login_key": None},
        {"login_key": ""},
        {"login_key": "   "},
        {"login_key": "a b"},
        {"login_key": "a\u200bb"},
        {"login_key": "a" * 256},
        {"login_key": "ok", "extra": 1},
        {"login_key": 7},
    ],
)
async def test_create_rejects_invalid_input(world: UsersWorld, body: dict[str, Any]) -> None:
    await world.request("POST", "", body, 422)
    assert await world.audit_rows() == []


async def test_create_strips_and_preserves_case(world: UsersWorld) -> None:
    row = (await world.request("POST", "", {"login_key": "  Bob  "}, 201)).json()
    assert row["login_key"] == "Bob"
    assert row["email"] is None and row["display_name"] is None
    await world.request("POST", "", {"login_key": "Bob"}, 409)
    assert (await world.request("POST", "", {"login_key": "bob"}, 201)).json()["login_key"] == "bob"
    assert (await world.request("POST", "", {"login_key": "a" * 255}, 201)).json()["login_key"] == (
        "a" * 255
    )


async def test_patch_updates_and_clears_fields(world: UsersWorld) -> None:
    patched = (
        await world.request("PATCH", "/2", {"display_name": "Helper", "email": "h@example.com"})
    ).json()
    assert patched["login_key"] == "helper"
    assert patched["display_name"] == "Helper"
    assert patched["email"] == "h@example.com"
    cleared = (await world.request("PATCH", "/2", {"email": None})).json()
    assert cleared["email"] is None
    assert cleared["display_name"] == "Helper"
    # An empty patch and a same-value rename are no-ops that still return the row.
    assert (await world.request("PATCH", "/2", {})).json() == cleared
    assert (await world.request("PATCH", "/2", {"login_key": "helper"})).json() == cleared
    await world.request("PATCH", "/2", {"login_key": None}, 422)
    await world.request("PATCH", "/9999", {"display_name": "x"}, 404)


async def test_patch_rename_and_duplicate_conflict(world: UsersWorld) -> None:
    await world.request("POST", "", {"login_key": "alice"}, 201)
    renamed = (await world.request("PATCH", "/3", {"login_key": "bob"})).json()
    assert renamed["login_key"] == "bob"
    assert (await world.request("GET", "/3")).json()["login_key"] == "bob"
    await world.request("PATCH", "/4", {"login_key": "alice"}, 409)


async def test_initial_admin_login_key_is_rename_protected(world: UsersWorld) -> None:
    response = await world.request("PATCH", "/1", {"login_key": "ruler"}, 403)
    assert "initial-admin" in response.json()["detail"]
    response = await world.request("PATCH", "/2", {"login_key": INITIAL}, 403)
    assert "initial-admin" in response.json()["detail"]
    assert (await world.request("GET", "/1")).json()["login_key"] == INITIAL
    assert (await world.request("GET", "/2")).json()["login_key"] == "helper"
    # Renaming between ordinary keys stays allowed for any admin.
    world.act_as(2, "helper")
    assert (await world.request("PATCH", "/3", {"login_key": "plain2"})).json()["login_key"] == (
        "plain2"
    )


async def test_disable_and_enable_rules(world: UsersWorld) -> None:
    # A caller cannot disable themselves, whatever they are.
    await world.request("POST", "/1/disable", code=403)
    world.act_as(2, "helper")
    await world.request("POST", "/2/disable", code=403)
    # An initial admin can never be disabled, not even by an ordinary admin.
    await world.request("POST", "/1/disable", code=403)
    # Only an initial admin may disable an admin account.
    response = await world.request("POST", "/4/disable", code=403)
    assert "initial admin" in response.json()["detail"]

    world.act_as(1, INITIAL)
    disabled = (await world.request("POST", "/4/disable")).json()
    assert disabled["disabled_at"] is not None
    assert disabled["is_admin"] is True
    assert disabled["disabled_at"].endswith("Z")

    # Any admin may disable a plain user; repeats are no-ops that keep the stamp.
    world.act_as(2, "helper")
    first = (await world.request("POST", "/3/disable")).json()
    again = (await world.request("POST", "/3/disable")).json()
    assert again["disabled_at"] == first["disabled_at"]
    assert (await world.request("POST", "/3/enable")).json()["disabled_at"] is None
    assert (await world.request("POST", "/3/enable")).json()["disabled_at"] is None

    await world.request("POST", "/9999/disable", code=404)
    await world.request("POST", "/9999/enable", code=404)


async def test_write_calls_record_admin_audit_rows(world: UsersWorld) -> None:
    created = (await world.request("POST", "", {"login_key": "alice"}, 201)).json()
    await world.request("PATCH", f"/{created['id']}", {"display_name": "Alice"})
    await world.request("POST", "/3/disable")
    await world.request("POST", "/3/enable")
    assert await world.audit_rows() == [
        {
            "kind": "admin",
            "user_id": 1,
            "detail": {
                "action": "create_user",
                "target_user_id": created["id"],
                "login_key": "alice",
            },
        },
        {
            "kind": "admin",
            "user_id": 1,
            "detail": {
                "action": "update_user",
                "target_user_id": created["id"],
                "changes": {"display_name": "Alice"},
            },
        },
        {
            "kind": "admin",
            "user_id": 1,
            "detail": {"action": "disable_user", "target_user_id": 3},
        },
        {
            "kind": "admin",
            "user_id": 1,
            "detail": {"action": "enable_user", "target_user_id": 3},
        },
    ]


async def test_rejected_calls_are_not_audited_and_repeats_are(world: UsersWorld) -> None:
    await world.request("POST", "", {"login_key": "alice"}, 201)
    await world.request("POST", "", {"login_key": "alice"}, 409)
    await world.request("PATCH", "/1", {"login_key": "ruler"}, 403)
    await world.request("POST", "/9999/disable", code=404)
    await world.request("GET", "/2")
    assert len(await world.audit_rows()) == 1
    # An idempotent disable still records the admin action.
    await world.request("POST", "/3/disable")
    await world.request("POST", "/3/disable")
    actions = [row["detail"]["action"] for row in await world.audit_rows()]
    assert actions == ["create_user", "disable_user", "disable_user"]


async def test_unbind_clears_the_bound_subject(world: UsersWorld) -> None:
    await world.bind(3, "subject-3")
    assert (await world.request("GET", "/3")).json()["oidc_bound"] is True
    world.act_as(2, "helper")
    # Any admin may unbind a plain user; repeats are no-ops that keep the flag off.
    unbound = (await world.request("POST", "/3/unbind")).json()
    assert unbound["login_key"] == "plain"
    assert unbound["oidc_bound"] is False
    assert (await world.request("POST", "/3/unbind")).json() == unbound
    assert (await world.request("GET", "/3")).json()["oidc_bound"] is False
    # Unbinding an admin account requires an initial-admin caller.
    await world.bind(4, "subject-4")
    response = await world.request("POST", "/4/unbind", code=403)
    assert "initial admin" in response.json()["detail"]
    world.act_as(1, INITIAL)
    assert (await world.request("POST", "/4/unbind")).json()["oidc_bound"] is False
    # An initial admin's subject is pinned in code: never unbound, by anyone.
    await world.bind(1, "subject-1")
    response = await world.request("POST", "/1/unbind", code=403)
    assert "pinned" in response.json()["detail"]
    world.act_as(2, "helper")
    await world.request("POST", "/1/unbind", code=403)
    await world.request("POST", "/9999/unbind", code=404)
    # Every accepted call is audited; rejected calls add nothing.
    assert [row["detail"] for row in await world.audit_rows()] == [
        {"action": "unbind_user", "target_user_id": 3},
        {"action": "unbind_user", "target_user_id": 3},
        {"action": "unbind_user", "target_user_id": 4},
    ]


async def test_promotion_after_the_fast_check_still_refuses_disable(
    world: UsersWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gate M3: the disable route re-reads admin status under the RuleService lock.

    Deterministic, no sleeps: the promotion is paused *inside* the lock before its
    tuple is written while an ordinary admin's disable performs its fast check; the
    disable must then wait for the promotion and be refused, not disable an admin.
    """
    rules = world.app.state.rules
    entered, release, checked = asyncio.Event(), asyncio.Event(), asyncio.Event()

    original_write = world.store.write

    async def gated_write(writes=(), deletes=()):
        if not entered.is_set():
            entered.set()
            await release.wait()
        await original_write(writes, deletes)

    original_check = world.store.check

    async def watching_check(user: str, relation: str, object: str) -> bool:
        result = await original_check(user, relation, object)
        if user == "user:3":
            checked.set()
        return result

    monkeypatch.setattr(world.store, "write", gated_write)
    monkeypatch.setattr(world.store, "check", watching_check)

    world.act_as(2, "helper")
    promotion = asyncio.create_task(rules.add_admin(AdminUser(1, INITIAL), 3))
    await asyncio.wait_for(entered.wait(), 2)
    disable = asyncio.create_task(world.request("POST", "/3/disable", code=403))
    await asyncio.wait_for(checked.wait(), 2)
    release.set()
    await asyncio.wait_for(promotion, 2)
    await asyncio.wait_for(disable, 2)

    row = (await world.request("GET", "/3")).json()
    assert row["is_admin"] is True
    assert row["disabled_at"] is None


async def test_login_binding_during_unbind_is_cleared_in_the_transaction(
    world: UsersWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gate2 G2-4: unbind writes and re-reads inside its transaction.

    The login flow's binding write commits while the unbind route is suspended in
    its authoritative admin check (after the in-lock row re-read). The
    unconditional ``oidc_sub = NULL`` must clear it, so the response, the audit
    row and the database all agree that the account is unbound.
    """
    target_checks = 0
    arrived, release = asyncio.Event(), asyncio.Event()
    original_check = world.store.check

    async def gated_check(user: str, relation: str, object: str) -> bool:
        nonlocal target_checks
        if user == "user:3":
            target_checks += 1
            if target_checks == 2:  # the in-lock authoritative check
                arrived.set()
                await release.wait()
        return await original_check(user, relation, object)

    monkeypatch.setattr(world.store, "check", gated_check)
    world.act_as(2, "helper")
    unbind = asyncio.create_task(world.request("POST", "/3/unbind", code=200))
    await asyncio.wait_for(arrived.wait(), 2)
    await world.bind(3, "subject-login")  # the binding write of a login flow
    release.set()
    body = (await asyncio.wait_for(unbind, 2)).json()
    assert body["oidc_bound"] is False
    async with world.app.state.metadata.execute(
        "SELECT oidc_sub FROM users WHERE id = 3"
    ) as cur:
        assert await cur.fetchone() == (None,)
    assert [row["detail"] for row in await world.audit_rows()] == [
        {"action": "unbind_user", "target_user_id": 3}
    ]


async def test_enable_during_disable_is_reflected_in_the_transaction(
    world: UsersWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same transaction pattern for disable: an enable that commits while the
    disable route is suspended in its admin check must be overwritten by the
    transaction's unconditional write, and the response must match the database."""
    await world.request("POST", "/3/disable")  # the target starts out disabled
    target_checks = 0
    arrived, release = asyncio.Event(), asyncio.Event()
    original_check = world.store.check

    async def gated_check(user: str, relation: str, object: str) -> bool:
        nonlocal target_checks
        if user == "user:3":
            target_checks += 1
            if target_checks == 2:  # the in-lock authoritative check
                arrived.set()
                await release.wait()
        return await original_check(user, relation, object)

    monkeypatch.setattr(world.store, "check", gated_check)
    world.act_as(2, "helper")
    disable = asyncio.create_task(world.request("POST", "/3/disable", code=200))
    await asyncio.wait_for(arrived.wait(), 2)
    await world.request("POST", "/3/enable")  # the concurrent enable commits
    release.set()
    body = (await asyncio.wait_for(disable, 2)).json()
    assert body["disabled_at"] is not None
    async with world.app.state.metadata.execute(
        "SELECT disabled_at FROM users WHERE id = 3"
    ) as cur:
        db_value = (await cur.fetchone())[0]
    assert db_value == body["disabled_at"]
