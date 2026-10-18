"""Admin HTTP boundary with a real OpenFGA store and a non-superuser target admin."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock

import httpx
import psycopg
import pytest
from fastapi import FastAPI
from psycopg.conninfo import make_conninfo
from psycopg.sql import SQL, Identifier, Literal

from db_gateway import metadata
from db_gateway.api.auth import current_user
from db_gateway.app import _check_connections, create_app
from db_gateway.permissions import ids
from db_gateway.permissions.admin import INITIAL_ADMINS, AdminUser
from db_gateway.permissions.context import TargetUnavailable
from db_gateway.permissions.executor import ApplyError
from db_gateway.permissions.ids import InvalidInput
from db_gateway.permissions.store import PermissionStoreUnavailable
from db_gateway.permissions.types import PgOp
from db_gateway.settings import Settings
from tests.conftest import RoleInfo
from tests.integration.test_target_db import TargetAdmin
from tests.integration.test_target_db import target_admin as target_admin


@dataclass
class ApiWorld:
    app: FastAPI
    client: httpx.AsyncClient
    admin: TargetAdmin
    registration: dict[str, Any]
    actor: AdminUser
    connect: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]]

    async def request(
        self, method: str, path: str, body: dict | None = None, code: int = 200
    ) -> httpx.Response:
        response = await self.client.request(method, "/api/admin" + path, json=body)
        assert response.status_code == code, response.text
        return response

    @property
    def policy(self) -> dict[str, str]:
        return {
            "connection": "target",
            "schema": self.admin.schema,
            "table": "items",
            "column": "team",
        }

    @property
    def table(self) -> dict[str, str]:
        return {"group": "analysts", **{k: v for k, v in self.policy.items() if k != "column"}}


@pytest.fixture
async def api_world(
    cluster_lock: psycopg.AsyncConnection | None,
    target_admin: TargetAdmin,
    superuser_conn: psycopg.AsyncConnection,
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
    fga_store: str,
    openfga_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[ApiWorld]:
    monkeypatch.setenv(
        "DBGW_SECRET_API_TEST",
        make_conninfo(user=target_admin.login.name, password=target_admin.login.password),
    )
    settings = Settings(
        metadata_db_path=tmp_path / "metadata.sqlite3",
        openfga_api_url=openfga_url,
        openfga_store_id=fga_store,
        sync_poll_interval_s=3600,
        reconcile_interval_s=3600,
    )
    app = create_app(settings)
    actor = AdminUser(1, sorted(INITIAL_ADMINS)[0])
    app.dependency_overrides[current_user] = lambda: actor
    async with app.router.lifespan_context(app):
        # HTTP sync/reconcile operations drive progression explicitly, never timing luck.
        app.state.reconciler.stop()
        await app.state.syncer.stop()
        await asyncio.gather(*app.state.permission_tasks)
        async with metadata.transaction(app.state.metadata):
            for user_id, login in ((1, actor.login_key), (2, "helper"), (3, "plain")):
                await app.state.metadata.execute(
                    "INSERT INTO users (id, login_key) VALUES (?, ?)", (user_id, login)
                )
        async with await connect_as(target_admin.login) as conn:
            await conn.execute(
                SQL("CREATE TABLE {} (team text NOT NULL)").format(
                    Identifier(target_admin.schema, "items")
                )
            )
            await conn.execute(
                SQL("INSERT INTO {} VALUES ('a'), ('b')").format(
                    Identifier(target_admin.schema, "items")
                )
            )
        registration = {
            "name": "target",
            "host": superuser_conn.info.host,
            "port": superuser_conn.info.port,
            "dbname": superuser_conn.info.dbname,
            "sslmode": "disable",
            "admin_secret_ref": "api-test",
            "default_privilege_owners": [target_admin.login.name],
        }
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            world = ApiWorld(app, client, target_admin, registration, actor, connect_as)
            await world.request("POST", "/connections", registration, 201)
            yield world


# Every route has a successful operation below and both identity/authorization failures here.
ROUTES = [
    ("GET", "/groups"),
    ("POST", "/groups"),
    ("DELETE", "/groups/analysts"),
    ("PUT", "/groups/analysts/description"),
    ("PUT", "/descriptions"),
    ("POST", "/groups/analysts/members"),
    ("DELETE", "/groups/analysts/members/3"),
    ("POST", "/grants/schema-reader"),
    ("DELETE", "/grants/schema-reader"),
    ("POST", "/grants/table-reader"),
    ("DELETE", "/grants/table-reader"),
    ("POST", "/grants/row-set"),
    ("DELETE", "/grants/row-set"),
    ("GET", "/rules"),
    ("GET", "/row-policies"),
    ("POST", "/row-policies"),
    ("DELETE", "/row-policies"),
    ("GET", "/connections"),
    ("POST", "/connections"),
    ("GET", "/sync"),
    ("POST", "/sync"),
    ("POST", "/reconcile"),
    ("GET", "/drift"),
    ("GET", "/admins"),
    ("POST", "/admins"),
    ("DELETE", "/admins/2"),
]


async def test_every_endpoint_requires_identity_and_admin(api_world: ApiWorld) -> None:
    w = api_world
    w.app.dependency_overrides.clear()
    for method, path in ROUTES:
        await w.request(method, path, code=401)
    w.app.dependency_overrides[current_user] = lambda: AdminUser(3, "plain")
    for method, path in ROUTES:
        await w.request(method, path, code=403)


async def test_groups_descriptions_members_grants_and_deletion(api_world: ApiWorld) -> None:
    w = api_world
    await w.request("POST", "/groups", {"name": "analysts", "description": "initial"}, 201)
    assert (await w.request("GET", "/groups")).json() == [
        {"name": "analysts", "description": "initial"}
    ]
    await w.request("PUT", "/groups/analysts/description", {"description": "new"})
    await w.request("PUT", "/descriptions", {"object_id": "group:analysts", "description": "shown"})
    assert (await w.request("GET", "/groups")).json()[0]["description"] == "shown"
    await w.request("POST", "/groups/analysts/members", {"user_id": 3}, 201)
    # Schema grant, list by both filters, then inline revoke.
    schema = {k: v for k, v in w.table.items() if k != "table"}
    await w.request("POST", "/grants/schema-reader", schema, 201)
    await w.request("POST", "/sync?connection=target")
    rows = (await w.request("GET", "/rules?group=analysts&connection=target")).json()
    assert rows == [
        {
            "user": ids.group_member("analysts"),
            "relation": "reader",
            "object": ids.db_schema("target", w.admin.schema),
        }
    ]
    conflict = await w.request("POST", "/grants/table-reader", w.table, 409)
    assert conflict.json()["conflicts"] == rows
    assert (await w.request("DELETE", "/grants/schema-reader", schema)).json() == {
        "status": "synced"
    }
    await w.request("POST", "/grants/table-reader", w.table, 201)
    await w.request("POST", "/sync")
    # Check a visible PG effect, not only the HTTP response.
    async with await w.connect(w.admin.login) as conn:
        cursor = await conn.execute(
            SQL("SELECT has_table_privilege('g_analysts', {}, 'SELECT')").format(
                Literal(Identifier(w.admin.schema, "items").as_string(conn))
            )
        )
        assert await cursor.fetchone() == (True,)
    assert (await w.request("DELETE", "/grants/table-reader", w.table)).json() == {
        "status": "synced"
    }
    await w.request("DELETE", "/groups/analysts/members/3")
    await w.request("DELETE", "/groups/analysts")
    assert (await w.request("GET", "/groups")).json() == []
    assert (await w.request("GET", "/sync")).json()[0]["last_error"] is None
    assert len((await w.request("GET", "/connections")).json()) == 1


async def test_row_policies_row_sets_and_conflicts(api_world: ApiWorld) -> None:
    w = api_world
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    await w.request("POST", "/row-policies", w.policy, 201)
    assert (await w.request("GET", "/row-policies?connection=target")).json() == [
        {"connection": "target", "schema": w.admin.schema, "table": "items", "column": "team"}
    ]
    row = {**w.table, "column": "team", "value": "a"}
    await w.request("POST", "/grants/row-set", row, 201)
    await w.request("POST", "/sync")
    await w.request(
        "DELETE", "/row-policies", {k: v for k, v in w.policy.items() if k != "column"}, 409
    )
    assert (await w.request("DELETE", "/grants/row-set", row)).json() == {"status": "synced"}
    await w.request("DELETE", "/row-policies", {k: v for k, v in w.policy.items() if k != "column"})
    assert (await w.request("GET", "/row-policies")).json() == []


async def test_reconcile_and_drift_dry_run_do_not_apply(api_world: ApiWorld) -> None:
    w = api_world
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    for method, path in (("POST", "/reconcile?dry_run=true"), ("GET", "/drift?connection=target")):
        report = (await w.request(method, path)).json()["target"]
        assert report["dry_run"] is True
        assert report["fixes"] == [{"op": "CreateGroupRole", "role": "g_analysts"}]
        async with await w.connect(w.admin.login) as conn:
            cursor = await conn.execute(SQL("SELECT 1 FROM pg_roles WHERE rolname = 'g_analysts'"))
            assert await cursor.fetchone() is None
    report = (await w.request("POST", "/reconcile?connection=target")).json()["target"]
    assert report["error"] is None
    assert report["fixes"] == [{"op": "CreateGroupRole", "role": "g_analysts"}]
    assert (await w.request("GET", "/drift")).json()["target"]["fixes"] == []


async def test_admin_merge_add_remove_and_restrictions(api_world: ApiWorld) -> None:
    w = api_world
    await w.request("POST", "/admins", {"user_id": 1}, 201)
    await w.request("POST", "/admins", {"user_id": 2}, 201)
    entries = (await w.request("GET", "/admins")).json()
    assert entries == [
        {"user_id": 1, "login_key": w.actor.login_key, "initial": True},
        {"user_id": 2, "login_key": "helper", "initial": False},
    ]
    w.app.dependency_overrides[current_user] = lambda: AdminUser(2, "helper")
    await w.request("POST", "/admins", {"user_id": 3}, 201)
    await w.request("DELETE", "/admins/3", code=403)
    w.app.dependency_overrides[current_user] = lambda: w.actor
    await w.request("DELETE", "/admins/1", code=403)
    await w.request("DELETE", "/admins/2")
    await w.request("DELETE", "/admins/2", code=404)
    await w.request("POST", "/admins", {"user_id": 9999}, 404)


async def test_resource_validation_and_not_found(api_world: ApiWorld) -> None:
    w = api_world
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    await w.request("POST", "/groups", {"name": "analysts"}, 409)
    await w.request("POST", "/groups", {"name": "bad name"}, 422)
    await w.request("PUT", "/descriptions", {"object_id": "bogus:x"}, 422)
    for method, path, body in (
        ("DELETE", "/groups/missing", None),
        ("PUT", "/groups/missing/description", {"description": "x"}),
        ("POST", "/groups/missing/members", {"user_id": 3}),
        ("DELETE", "/groups/missing/members/3", None),
        ("GET", "/rules?group=missing", None),
        ("GET", "/row-policies?connection=missing", None),
        ("POST", "/sync?connection=missing", None),
        ("POST", "/reconcile?connection=missing", None),
        ("GET", "/drift?connection=missing", None),
        ("DELETE", "/row-policies", {k: v for k, v in w.policy.items() if k != "column"}),
    ):
        await w.request(method, path, body, 404)
    for kind in ("schema-reader", "table-reader", "row-set"):
        body = {**w.table, "group": "missing"}
        if kind == "schema-reader":
            del body["table"]
        if kind == "row-set":
            body.update(column="team", value="a")
        for method in ("POST", "DELETE"):
            await w.request(method, "/grants/" + kind, body, 404)
    await w.request("POST", "/row-policies", {**w.policy, "column": "missing"}, 422)
    await w.request("POST", "/row-policies", {**w.policy, "connection": "missing"}, 404)


@pytest.mark.parametrize("owners", ["owner", [""], [" "], [42], None])
async def test_connection_owner_input_validation(api_world: ApiWorld, owners: Any) -> None:
    await api_world.request(
        "POST", "/connections", {**api_world.registration, "default_privilege_owners": owners}, 422
    )


async def test_connection_setup_failure_is_read_only_and_rejected(api_world: ApiWorld) -> None:
    w = api_world
    await w.request("POST", "/connections", w.registration, 409)
    async with await w.connect(w.admin.login) as conn:
        await conn.execute(
            SQL("REVOKE EXECUTE ON FUNCTION gateway_acl.allowed_values(name, name) FROM PUBLIC")
        )
    response = await w.request("POST", "/connections", {**w.registration, "name": "other"}, 422)
    assert "function_public_execute" in {p["code"] for p in response.json()["detail"]["missing"]}
    assert len((await w.request("GET", "/connections")).json()) == 1
    async with await w.connect(w.admin.login) as conn:
        cursor = await conn.execute(
            SQL(
                "SELECT has_function_privilege("
                "'gw_managed', 'gateway_acl.allowed_values(name, name)', 'EXECUTE')"
            )
        )
        assert await cursor.fetchone() == (False,)


async def test_permission_store_unavailable_mapping(
    api_world: ApiWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        api_world.app.state.store,
        "read",
        AsyncMock(side_effect=PermissionStoreUnavailable("offline")),
    )
    await api_world.request("GET", "/groups", code=503)
    api_world.app.dependency_overrides[current_user] = lambda: AdminUser(2, "helper")
    monkeypatch.setattr(
        api_world.app.state.store,
        "check",
        AsyncMock(side_effect=PermissionStoreUnavailable("offline")),
    )
    await api_world.request("GET", "/admins", code=503)


async def test_revoke_and_undeclare_pending_statuses(
    api_world: ApiWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = api_world
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    await w.request("POST", "/grants/table-reader", w.table, 201)
    await w.request("POST", "/row-policies", w.policy, 201)
    await w.request("POST", "/sync")
    # A real queued inline revoke times out while another PG unit owns the shared lock.
    w.app.state.rules._revoke_timeout = 0
    lock = w.app.state.locks("target")
    async with lock:
        response = await w.request("DELETE", "/grants/table-reader", w.table, 202)
        assert response.json() == {"status": "pending"}
        pending = list(w.app.state.syncer._inline_tasks)
        assert pending
    assert all(await asyncio.wait_for(asyncio.gather(*pending), 5))
    async with await w.connect(w.admin.login) as conn:
        await conn.execute(SQL("DROP TABLE {}").format(Identifier(w.admin.schema, "items")))
    # DisableRowPolicy is skipped for the missing table: a non-None error means pending.
    response = await w.request(
        "DELETE", "/row-policies", {k: v for k, v in w.policy.items() if k != "column"}, 202
    )
    assert response.json() == {"status": "pending"}
    assert (await w.request("GET", "/row-policies")).json() == []


@pytest.mark.parametrize("failure", ["missing", "malformed", "invalid", "connect", "password"])
async def test_unavailable_target_is_sanitized_503_for_grants_policies_and_reports(
    api_world: ApiWorld,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure: str,
) -> None:
    w = api_world
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    if failure == "missing":
        monkeypatch.delenv("DBGW_SECRET_API_TEST")
    elif failure == "malformed":
        monkeypatch.setenv("DBGW_SECRET_API_TEST", "user=admin password=abc PRIVATE_FRAGMENT")
    elif failure == "invalid":
        monkeypatch.setenv("DBGW_SECRET_API_TEST", "password=PRIVATE_FRAGMENT")
    else:
        error = (
            psycopg.errors.InvalidPassword("PRIVATE_FRAGMENT")
            if failure == "password"
            else psycopg.OperationalError("PRIVATE_FRAGMENT")
        )
        monkeypatch.setattr(
            "db_gateway.permissions.context.psycopg.AsyncConnection.connect",
            AsyncMock(side_effect=error),
        )
    reason = (
        "credentials invalid"
        if failure == "password"
        else "connect failed"
        if failure == "connect"
        else "secret missing or invalid"
    )
    before = await w.app.state.store.read()
    schema = {k: v for k, v in w.table.items() if k != "table"}
    for method, path, body in (
        ("POST", "/grants/schema-reader", schema),
        ("POST", "/grants/table-reader", w.table),
        ("POST", "/row-policies", w.policy),
        ("POST", "/reconcile?connection=target", None),
        ("GET", "/drift?connection=target", None),
        ("POST", "/reconcile", None),
        ("GET", "/drift", None),
    ):
        code = 200 if path in {"/reconcile", "/drift"} else 503
        response = await w.request(method, path, body, code)
        result = response.json()
        if path.startswith(("/reconcile", "/drift")):
            assert result["target"]["target_unavailable"] is True
            assert reason in result["target"]["error"]
        else:
            assert reason in result["detail"]
        if failure == "password":
            assert "InvalidPassword" in response.text and "28P01" in response.text
        assert "PRIVATE_FRAGMENT" not in response.text
    assert await w.app.state.store.read() == before
    assert "PRIVATE_FRAGMENT" not in caplog.text


async def test_unavailable_target_during_distinct_count_returns_503(
    api_world: ApiWorld,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    w = api_world
    monkeypatch.setattr(
        w.app.state.rules._stats,
        "_connect",
        AsyncMock(
            side_effect=TargetUnavailable(
                "target", "connect failed", psycopg.OperationalError("PRIVATE_FRAGMENT")
            )
        ),
    )
    before = await w.app.state.store.read()
    response = await w.request("POST", "/row-policies", w.policy, 503)
    assert "connect failed" in response.json()["detail"]
    assert "PRIVATE_FRAGMENT" not in response.text
    assert await w.app.state.store.read() == before


@pytest.mark.parametrize(
    "secret",
    [
        None,
        "user=admin password=abc PRIVATE_FRAGMENT",
        "password=PRIVATE_FRAGMENT",
        "user=admin host=PRIVATE_FRAGMENT",
    ],
)
async def test_registration_and_startup_logs_never_echo_invalid_secret_fragments(
    api_world: ApiWorld,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    secret: str | None,
) -> None:
    w = api_world
    if secret is None:
        monkeypatch.delenv("DBGW_SECRET_API_TEST")
    else:
        monkeypatch.setenv("DBGW_SECRET_API_TEST", secret)
    response = await w.request("POST", "/connections", {**w.registration, "name": "other"}, 422)
    missing = response.json()["detail"]["missing"]
    assert missing == [
        {
            "code": "connection_check_failed",
            "message": "secret api-test missing or not a valid credentials fragment",
            "remediation": None,
        }
    ]
    await _check_connections(w.app)
    assert "Target setup problems on target" in caplog.text
    assert "PRIVATE_FRAGMENT" not in response.text
    assert "PRIVATE_FRAGMENT" not in caplog.text
    assert len((await w.request("GET", "/connections")).json()) == 1


@pytest.mark.parametrize("query", ["", "?connection=target"])
async def test_single_and_all_reconcile_paths_preserve_other_error_reports(
    api_world: ApiWorld,
    monkeypatch: pytest.MonkeyPatch,
    query: str,
) -> None:
    monkeypatch.setattr(
        "db_gateway.permissions.reconciler._snapshot",
        AsyncMock(side_effect=RuntimeError("catalog failed")),
    )
    for method, path in (("POST", "/reconcile"), ("GET", "/drift")):
        response = await api_world.request(method, path + query)
        assert response.json()["target"]["error"] == "RuntimeError: catalog failed"
        assert response.json()["target"]["target_unavailable"] is False


@pytest.mark.parametrize("method, path", [("POST", "/reconcile"), ("GET", "/drift")])
async def test_bulk_reports_keep_healthy_target_when_other_target_is_down(
    api_world: ApiWorld, method: str, path: str
) -> None:
    w = api_world
    await w.request("POST", "/connections", {**w.registration, "name": "other"}, 201)
    async with metadata.transaction(w.app.state.metadata):
        await w.app.state.metadata.execute(
            "UPDATE connections SET admin_secret_ref = 'absent' WHERE name = 'other'"
        )
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    response = await w.request(method, path)
    reports = response.json()
    assert set(reports) == {"target", "other"}
    assert reports["target"]["error"] is None
    assert {"op": "CreateGroupRole", "role": "g_analysts"} in reports["target"]["fixes"]
    assert reports["target"]["dry_run"] is (method == "GET")
    assert reports["other"]["target_unavailable"]
    assert "secret missing or invalid" in reports["other"]["error"]
    async with await w.connect(w.admin.login) as conn:
        cursor = await conn.execute(
            SQL("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'g_analysts')")
        )
        assert await cursor.fetchone() == (method == "POST",)


async def test_single_target_unavailable_response_preserves_applied_fixes(
    api_world: ApiWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = api_world
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    await w.request("POST", "/grants/table-reader", w.table, 201)
    executor = w.app.state.executor
    original_apply = executor.apply

    async def apply(connection: str, ops: Sequence[PgOp]) -> Sequence[PgOp]:
        if any(type(op).__name__ != "CreateGroupRole" for op in ops):
            raise ApplyError(
                connection,
                None,
                TargetUnavailable(
                    connection, "connect failed", psycopg.OperationalError("PRIVATE")
                ),
            )
        return await original_apply(connection, ops)

    monkeypatch.setattr(executor, "apply", apply)
    response = await w.request("POST", "/reconcile?connection=target", code=503)
    report = response.json()["target"]
    assert report["target_unavailable"]
    assert {"op": "CreateGroupRole", "role": "g_analysts"} in report["fixes"]
    assert {op["op"] for op in report["failed"]} == {"GrantTableSelect", "UpsertRowGrant"}
    assert "connect failed" in report["error"] and "PRIVATE" not in response.text
    async with await w.connect(w.admin.login) as conn:
        cursor = await conn.execute(
            SQL("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'g_analysts')")
        )
        assert await cursor.fetchone() == (True,)


@pytest.mark.parametrize("stage", ["scan", "distinct", "apply"])
@pytest.mark.parametrize(
    "error_type",
    [
        psycopg.errors.QueryCanceled,
        psycopg.errors.LockNotAvailable,
        psycopg.errors.DeadlockDetected,
        psycopg.OperationalError,
    ],
)
async def test_query_errors_return_safe_503_and_ordinary_reconcile_reports(
    api_world: ApiWorld,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    stage: str,
    error_type: type[psycopg.OperationalError],
) -> None:
    w = api_world
    await w.request("POST", "/groups", {"name": "analysts"}, 201)
    error = error_type("PRIVATE")
    before = await w.app.state.store.read()
    if stage == "scan":
        monkeypatch.setattr("db_gateway.app.scan.unsafe_views", AsyncMock(side_effect=error))
    elif stage == "distinct":
        original = w.app.state.rules._stats._connect

        async def connect(connection: str) -> psycopg.AsyncConnection:
            conn = await original(connection)
            monkeypatch.setattr(conn, "execute", AsyncMock(side_effect=error))
            return conn

        monkeypatch.setattr(w.app.state.rules._stats, "_connect", connect)
    else:
        monkeypatch.setattr(
            w.app.state.executor,
            "apply",
            AsyncMock(side_effect=ApplyError("target", None, error)),
        )
    if stage == "scan":
        schema = {k: v for k, v in w.table.items() if k != "table"}
        for path, body in (("/grants/schema-reader", schema), ("/grants/table-reader", w.table)):
            response = await w.request("POST", path, body, 503)
            assert response.json() == {
                "detail": "target target query failed",
                "sqlstate": error.sqlstate,
                "error": error_type.__name__,
            }
    response = await w.request("POST", "/row-policies", w.policy, 503)
    assert response.json() == {
        "detail": "target target query failed",
        "sqlstate": error.sqlstate,
        "error": error_type.__name__,
    }
    assert await w.app.state.store.read() == before
    if stage == "distinct":
        monkeypatch.setattr(
            "db_gateway.permissions.reconciler._snapshot", AsyncMock(side_effect=error)
        )
    for method, path in (("POST", "/reconcile"), ("GET", "/drift")):
        for suffix in ("", "?connection=target"):
            report = (await w.request(method, path + suffix)).json()["target"]
            if stage == "apply" and method == "GET":
                # Dry-run plans repairs without invoking the failing executor.
                assert report["error"] is None
            else:
                assert report["target_unavailable"] is False
                assert error_type.__name__ in report["error"]
                assert str(error.sqlstate) in report["error"]
            assert "PRIVATE" not in str(report)
    assert error_type.__name__ in caplog.text and str(error.sqlstate) in caplog.text
    assert "PRIVATE" not in caplog.text


async def test_distinct_column_without_equality_returns_422(api_world: ApiWorld) -> None:
    w = api_world
    async with await w.connect(w.admin.login) as conn:
        await conn.execute(
            SQL("ALTER TABLE {} ADD COLUMN payload json").format(
                Identifier(w.admin.schema, "items")
            )
        )
    response = await w.request("POST", "/row-policies", {**w.policy, "column": "payload"}, 422)
    assert response.json() == {
        "detail": "column payload cannot be used for row control: no equality operator"
    }
    assert (await w.request("GET", "/row-policies")).json() == []


async def test_target_drops_after_scan_and_count_during_declaration(
    api_world: ApiWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = api_world
    monkeypatch.setattr(
        w.app.state.executor,
        "_connect",
        AsyncMock(
            side_effect=TargetUnavailable(
                "target", "connect failed", psycopg.OperationalError("PRIVATE")
            )
        ),
    )
    response = await w.request("POST", "/row-policies", w.policy, 503)
    assert "connect failed" in response.json()["detail"]
    assert (await w.request("GET", "/row-policies")).json() == []
    async with w.app.state.metadata.execute(
        "SELECT error FROM audit_log WHERE error IS NOT NULL"
    ) as cursor:
        errors = await cursor.fetchall()
    assert len(errors) == 1
    assert "TargetUnavailable" in errors[0][0] and "PRIVATE" not in errors[0][0]
    assert "PRIVATE" not in response.text


@pytest.mark.parametrize(
    "error, code", [(InvalidInput("bad input"), 422), (ValueError("PRIVATE"), 500)]
)
async def test_only_domain_input_errors_map_to_422(
    api_world: ApiWorld,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    code: int,
) -> None:
    w = api_world
    monkeypatch.setattr(w.app.state.rules, "list_groups", AsyncMock(side_effect=error))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=w.app, raise_app_exceptions=False), base_url="http://test"
    ) as client:
        response = await client.get("/api/admin/groups")
    assert response.status_code == code
    if code == 500:
        assert "PRIVATE" not in response.text


async def test_only_initial_admin_can_register_connections(api_world: ApiWorld) -> None:
    w = api_world
    await w.request("POST", "/connections", {**w.registration, "name": "second"}, 201)
    assert {row["name"] for row in (await w.request("GET", "/connections")).json()} == {
        "target",
        "second",
    }


@pytest.mark.parametrize("valid_body", [True, False])
async def test_ordinary_admin_registration_is_rejected_before_credentials_or_target_access(
    api_world: ApiWorld,
    monkeypatch: pytest.MonkeyPatch,
    valid_body: bool,
) -> None:
    w = api_world
    await w.request("POST", "/admins", {"user_id": 2}, 201)
    w.app.dependency_overrides[current_user] = lambda: AdminUser(2, "helper")
    validate = AsyncMock(side_effect=AssertionError("must not validate target"))
    resolve = Mock(side_effect=AssertionError("must not resolve credentials"))
    monkeypatch.setattr("db_gateway.api.admin_permissions.validate_connection", validate)
    monkeypatch.setattr("db_gateway.api.admin_permissions.admin_conninfo", resolve)
    db = w.app.state.metadata
    async with db.execute("SELECT count(*) FROM audit_log") as cursor:
        before = await cursor.fetchone()
    body = {**w.registration, "name": "denied"} if valid_body else {}
    await w.request("POST", "/connections", body, 403)
    validate.assert_not_awaited()
    resolve.assert_not_called()
    assert len((await w.request("GET", "/connections")).json()) == 1
    async with db.execute("SELECT count(*) FROM audit_log") as cursor:
        assert await cursor.fetchone() == before
