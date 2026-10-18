import asyncio
from pathlib import Path
from typing import Literal
from unittest.mock import AsyncMock, Mock

import httpx
import psycopg
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from db_gateway import metadata
from db_gateway.api.admin_permissions import validate_connection
from db_gateway.api.auth import current_user, permission_store
from db_gateway.app import TargetPartitionStats, TargetScanner, create_app, permission_error
from db_gateway.permissions import ids
from db_gateway.permissions.admin import INITIAL_ADMINS, AdminUser
from db_gateway.permissions.context import (
    ConnectionInfo,
    ConnectionLocks,
    TargetQueryFailed,
    admin_connector,
)
from db_gateway.permissions.executor import ApplyError
from db_gateway.permissions.ids import InvalidInput
from db_gateway.permissions.reconciler import Reconciler
from db_gateway.permissions.rules import TargetUnavailable
from db_gateway.permissions.store import PermissionStoreUnavailable
from db_gateway.permissions.store_memory import MemoryStore
from db_gateway.permissions.syncer import Syncer
from db_gateway.permissions.types import CreateGroupRole
from db_gateway.settings import Settings, get_settings


def test_health_and_metadata_lifecycle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "nested" / "metadata.sqlite3"
    monkeypatch.setenv("DBGW_METADATA_DB_PATH", str(path))
    get_settings.cache_clear()
    try:
        app = create_app()
        with TestClient(app) as client:
            response = client.get("/healthz")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}
            assert path.exists()

            async def schema_version() -> list[tuple[int]]:
                async with app.state.metadata.execute("SELECT version FROM schema_version") as cur:
                    return await cur.fetchall()

            assert client.portal is not None
            assert client.portal.call(schema_version) == [(1,), (2,)]
        with pytest.raises(ValueError, match="no active connection"):
            asyncio.run(schema_version())
    finally:
        get_settings.cache_clear()


async def test_services_share_locks_startup_reconcile_and_clean_shutdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("db_gateway.app.OpenFgaStore.ensure_model", AsyncMock(return_value="model"))
    started = asyncio.Event()
    reconciled = asyncio.Event()
    original_run = Syncer.run

    async def run(syncer: Syncer) -> None:
        started.set()
        await original_run(syncer)

    async def reconcile_all(reconciler: Reconciler, dry_run: bool = False) -> dict:
        reconciled.set()
        return {}

    monkeypatch.setattr(Syncer, "run", run)
    monkeypatch.setattr(Reconciler, "reconcile_all", reconcile_all)
    app = create_app(
        Settings(
            metadata_db_path=tmp_path / "db",
            openfga_store_id="store",
            sync_poll_interval_s=3600,
            reconcile_interval_s=3600,
        )
    )
    async with app.router.lifespan_context(app):
        await asyncio.wait_for(started.wait(), 2)
        await asyncio.wait_for(reconciled.wait(), 2)
        state = app.state
        assert state.rules._locks is state.syncer._locks is state.reconciler._locks is state.locks
        assert state.rules._executor is state.syncer._executor is state.reconciler._executor
        assert state.rules._executor is state.executor
        assert state.rules._inline is state.syncer
        assert state.rules._scanner is not None
        assert state.syncer._full_reconcile == state.reconciler.reconcile_strict
        assert state.executor._connect is state.reconciler._connect
        assert state.executor._connect is state.rules._scanner._connect
        assert state.executor._connect is state.rules._stats._connect
        tasks = state.permission_tasks
    assert len(tasks) == 3
    assert all(task.done() and (task.cancelled() or task.exception() is None) for task in tasks)


async def test_unavailable_openfga_still_starts_and_admin_requests_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(
        "db_gateway.app.OpenFgaStore.ensure_model",
        AsyncMock(side_effect=PermissionStoreUnavailable("offline")),
    )
    monkeypatch.setattr("db_gateway.app.admin.INITIAL_ADMINS", frozenset())
    app = create_app(Settings(metadata_db_path=tmp_path / "db", openfga_store_id="store"))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            assert (await client.get("/healthz")).status_code == 200
            assert (await client.get("/api/admin/groups")).status_code == 401
            app.dependency_overrides[current_user] = lambda: AdminUser(
                1, next(iter(INITIAL_ADMINS))
            )
            assert (await client.get("/api/admin/groups")).status_code == 503
    assert "INITIAL_ADMINS is empty" in caplog.text


@pytest.mark.parametrize("task_name", ["permission-sync", "permission-reconcile"])
async def test_dead_background_task_still_closes_store_and_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    task_name: str,
) -> None:
    monkeypatch.setattr("db_gateway.app.OpenFgaStore.ensure_model", AsyncMock(return_value="model"))
    method = (
        "db_gateway.app.Syncer.run"
        if task_name == "permission-sync"
        else "db_gateway.app.Reconciler.run_periodic"
    )
    monkeypatch.setattr(method, AsyncMock(side_effect=RuntimeError("worker died")))
    app = create_app(Settings(metadata_db_path=tmp_path / "db", openfga_store_id="store"))
    async with app.router.lifespan_context(app):
        dead = next(t for t in app.state.permission_tasks if t.get_name() == task_name)
        with pytest.raises(RuntimeError, match="worker died"):
            await dead
        close = AsyncMock(wraps=app.state.store.aclose)
        monkeypatch.setattr(app.state.store, "aclose", close)
    close.assert_awaited_once()
    with pytest.raises(ValueError, match="no active connection"):
        await app.state.metadata.execute("SELECT 1")
    assert task_name in caplog.text and "worker died" in caplog.text


async def test_blocked_startup_target_check_does_not_block_health_or_shutdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "db"
    db = await metadata.connect(path)
    try:
        await metadata.migrate(db)
        async with metadata.transaction(db):
            await db.execute(
                "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
                "VALUES ('prod', 'h', 'd', 'ref')"
            )
    finally:
        await db.close()
    checking = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()

    async def validate(info: ConnectionInfo) -> list:
        checking.set()
        try:
            await release.wait()
        finally:
            cancelled.set()
        return []

    monkeypatch.setattr("db_gateway.app.validate_connection", validate)
    monkeypatch.setattr("db_gateway.app.OpenFgaStore.ensure_model", AsyncMock(return_value="model"))
    monkeypatch.setattr(Syncer, "run", AsyncMock(return_value=None))
    monkeypatch.setattr(Reconciler, "run_periodic", AsyncMock(return_value=None))
    app = create_app(Settings(metadata_db_path=path, openfga_store_id="store"))
    async with asyncio.timeout(5), app.router.lifespan_context(app):
        await asyncio.wait_for(checking.wait(), 2)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await asyncio.wait_for(client.get("/healthz"), 2)
            assert response.status_code == 200
        assert not release.is_set()
    assert cancelled.is_set()
    assert all(task.done() for task in app.state.permission_tasks)


async def test_validation_connect_timeout_and_connect_error_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    info = ConnectionInfo(1, "prod", "h", 5432, "d", "disable", "ref", ())
    monkeypatch.setenv("DBGW_SECRET_REF", "user=admin password=password")
    connection = AsyncMock()
    connection.__aenter__.return_value = connection
    connect = AsyncMock(return_value=connection)
    check = AsyncMock(return_value=[])
    monkeypatch.setattr("db_gateway.api.admin_permissions.psycopg.AsyncConnection.connect", connect)
    monkeypatch.setattr("db_gateway.api.admin_permissions.check_target_db", check)
    assert await validate_connection(info) == []
    assert connect.call_args.kwargs == {"connect_timeout": 5}
    connect.side_effect = psycopg.OperationalError("connect failed")
    problems = await validate_connection(info)
    assert problems[0]["message"] == "connect failed"


@pytest.mark.parametrize("adapter", [TargetScanner, TargetPartitionStats])
async def test_target_connection_failures_are_sanitized(
    adapter: type[TargetScanner] | type[TargetPartitionStats],
) -> None:
    error = TargetUnavailable("prod", "secret missing or invalid", KeyError("PRIVATE"))
    connector = AsyncMock(side_effect=error)
    target = adapter(connector)
    with pytest.raises(TargetUnavailable) as failure:
        if isinstance(target, TargetScanner):
            await target.unsafe_views("prod", {("s", "t")})
        else:
            await target.distinct_count("prod", "s", "t", "team", 10)
    assert failure.value is error
    assert "PRIVATE" not in str(failure.value)


@pytest.mark.parametrize(
    "stage, error, reason",
    [
        ("secret", KeyError("PRIVATE"), "secret missing or invalid"),
        ("secret", ValueError("PRIVATE"), "secret missing or invalid"),
        ("secret", psycopg.ProgrammingError("PRIVATE"), "secret missing or invalid"),
        ("connect", psycopg.OperationalError("PRIVATE"), "connect failed"),
        ("connect", psycopg.errors.InvalidPassword("PRIVATE"), "credentials invalid"),
        (
            "connect",
            psycopg.errors.InvalidAuthorizationSpecification("PRIVATE"),
            "credentials invalid",
        ),
    ],
)
async def test_runtime_acquisition_reason_and_diagnostics_are_safe(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    stage: str,
    error: Exception,
    reason: str,
) -> None:
    info = ConnectionInfo(1, "prod", "h", 5432, "d", "disable", "ref", ())
    monkeypatch.setattr(
        "db_gateway.permissions.context.load_connection", AsyncMock(return_value=info)
    )
    monkeypatch.setattr(
        "db_gateway.permissions.context.admin_conninfo",
        Mock(return_value="user=admin"),
    )
    if stage == "secret":
        monkeypatch.setattr(
            "db_gateway.permissions.context.admin_conninfo", Mock(side_effect=error)
        )
    else:
        monkeypatch.setattr(
            "db_gateway.permissions.context.psycopg.AsyncConnection.connect",
            AsyncMock(side_effect=error),
        )
    db = await metadata.connect(":memory:")
    try:
        with pytest.raises(TargetUnavailable) as failure:
            await admin_connector(db)("prod")
        assert failure.value.reason == reason
        assert type(error).__name__ in str(failure.value)
        assert reason in str(failure.value) and reason in caplog.text
        if isinstance(error, psycopg.Error) and error.sqlstate:
            assert error.sqlstate in str(failure.value) and error.sqlstate in caplog.text
        assert "PRIVATE" not in str(failure.value) + caplog.text
        assert failure.value.__suppress_context__
    finally:
        await db.close()


@pytest.mark.parametrize("timeout_s", [None, 9])
async def test_runtime_connector_applies_default_and_configured_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timeout_s: int | None
) -> None:
    monkeypatch.setattr("db_gateway.app.OpenFgaStore.ensure_model", AsyncMock(return_value="model"))
    monkeypatch.setattr(Syncer, "run", AsyncMock(return_value=None))
    monkeypatch.setattr(Reconciler, "run_periodic", AsyncMock(return_value=None))
    settings = Settings(metadata_db_path=tmp_path / "db", openfga_store_id="store")
    if timeout_s is not None:
        settings.target_connect_timeout_s = timeout_s
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        info = ConnectionInfo(1, "prod", "h", 5432, "d", "disable", "ref", ())
        monkeypatch.setattr(
            "db_gateway.permissions.context.load_connection", AsyncMock(return_value=info)
        )
        monkeypatch.setenv("DBGW_SECRET_REF", "user=admin")
        connect = AsyncMock(side_effect=psycopg.OperationalError("PRIVATE"))
        monkeypatch.setattr(
            "db_gateway.permissions.context.psycopg.AsyncConnection.connect", connect
        )
        for connector in (
            app.state.executor._connect,
            app.state.syncer._executor._connect,
            app.state.reconciler._connect,
            app.state.rules._scanner._connect,
            app.state.rules._stats._connect,
        ):
            with pytest.raises(TargetUnavailable):
                await connector("prod")
        assert connect.await_count == 5
        assert all(
            call.kwargs == {"connect_timeout": timeout_s or 5} for call in connect.await_args_list
        )


@pytest.mark.parametrize("adapter", [TargetScanner, TargetPartitionStats])
@pytest.mark.parametrize(
    "error_type",
    [
        psycopg.errors.QueryCanceled,
        psycopg.errors.LockNotAvailable,
        psycopg.errors.DeadlockDetected,
        psycopg.errors.SerializationFailure,
        psycopg.errors.DiskFull,
        psycopg.errors.OutOfMemory,
        psycopg.errors.TooManyConnections,
        psycopg.errors.AdminShutdown,
        psycopg.errors.InvalidPassword,
        psycopg.errors.InvalidAuthorizationSpecification,
        psycopg.errors.ConnectionFailure,
        psycopg.OperationalError,
    ],
)
async def test_query_failures_keep_safe_class_and_sqlstate(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    adapter: type[TargetScanner] | type[TargetPartitionStats],
    error_type: type[psycopg.OperationalError],
) -> None:
    conn = AsyncMock()
    conn.__aenter__.return_value = conn
    error = error_type("PRIVATE")
    conn.execute.side_effect = error
    monkeypatch.setattr("db_gateway.app.scan.unsafe_views", AsyncMock(side_effect=error))
    target = adapter(AsyncMock(return_value=conn))
    with pytest.raises(TargetQueryFailed) as failure:
        if isinstance(target, TargetScanner):
            await target.unsafe_views("prod", {("s", "t")})
        else:
            await target.distinct_count("prod", "s", "t", "team", 10)
    assert failure.value.error == error_type.__name__
    assert failure.value.sqlstate == error.sqlstate
    assert error_type.__name__ in caplog.text and str(error.sqlstate) in caplog.text
    assert "PRIVATE" not in caplog.text + str(failure.value)


async def test_target_stats_column_validation_is_invalid_input() -> None:
    conn = AsyncMock()
    conn.__aenter__.return_value = conn
    conn.execute.side_effect = psycopg.errors.UndefinedColumn("missing")
    stats = TargetPartitionStats(AsyncMock(return_value=conn))
    with pytest.raises(InvalidInput):
        await stats.distinct_count("prod", "s", "t", "missing", 10)


async def test_concurrent_lazy_model_initialization_runs_once() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    contended = asyncio.Event()

    class ObservedLock(asyncio.Lock):
        async def acquire(self) -> Literal[True]:
            if self.locked():
                contended.set()
            return await super().acquire()

    async def ensure() -> str:
        entered.set()
        await release.wait()
        return "model"

    app = FastAPI()
    app.state.store = AsyncMock()
    app.state.store.ensure_model.side_effect = ensure
    app.state.store_ready = False
    app.state.store_model_lock = ObservedLock()
    request = Request({"type": "http", "app": app})
    first = asyncio.create_task(permission_store(request))
    second: asyncio.Task | None = None
    try:
        await asyncio.wait_for(entered.wait(), 2)
        second = asyncio.create_task(permission_store(request))
        await asyncio.wait_for(contended.wait(), 2)
        app.state.store.ensure_model.assert_awaited_once()
        release.set()
        results = await asyncio.wait_for(asyncio.gather(first, second), 2)
        assert results == [app.state.store, app.state.store]
        app.state.store.ensure_model.assert_awaited_once()
        assert app.state.store.read.await_count == 2
        assert app.state.store_ready
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)


async def test_failed_lazy_initialization_releases_lock_for_retry() -> None:
    app = FastAPI()
    app.state.store = AsyncMock()
    app.state.store.ensure_model.side_effect = [PermissionStoreUnavailable("offline"), "model"]
    app.state.store_ready = False
    app.state.store_model_lock = asyncio.Lock()
    request = Request({"type": "http", "app": app})
    with pytest.raises(PermissionStoreUnavailable):
        await permission_store(request)
    assert not app.state.store_model_lock.locked() and not app.state.store_ready
    assert await permission_store(request) is app.state.store
    assert app.state.store.ensure_model.await_count == 2 and app.state.store_ready


@pytest.mark.parametrize("adapter", [TargetScanner, TargetPartitionStats])
async def test_unexpected_valueerror_during_queries_is_not_input_or_availability_error(
    adapter: type[TargetScanner] | type[TargetPartitionStats],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = AsyncMock()
    conn.__aenter__.return_value = conn
    error = ValueError("internal query bug")
    conn.execute.side_effect = error
    monkeypatch.setattr("db_gateway.app.scan.unsafe_views", AsyncMock(side_effect=error))
    target = adapter(AsyncMock(return_value=conn))
    with pytest.raises(ValueError) as failure:
        if isinstance(target, TargetScanner):
            await target.unsafe_views("prod", {("s", "t")})
        else:
            await target.distinct_count("prod", "s", "t", "team", 10)
    assert type(failure.value) is ValueError


async def test_shared_executor_connector_does_not_echo_bad_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("db_gateway.app.OpenFgaStore.ensure_model", AsyncMock(return_value="model"))
    monkeypatch.setattr(Syncer, "run", AsyncMock(return_value=None))
    monkeypatch.setattr(Reconciler, "run_periodic", AsyncMock(return_value=None))
    monkeypatch.setenv("DBGW_SECRET_REF", "user=admin password=abc PRIVATE_FRAGMENT")
    app = create_app(Settings(metadata_db_path=tmp_path / "db", openfga_store_id="store"))
    async with app.router.lifespan_context(app):
        async with metadata.transaction(app.state.metadata):
            await app.state.metadata.execute(
                "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
                "VALUES ('prod', 'h', 'd', 'ref')"
            )
        with pytest.raises(ApplyError) as failure:
            await app.state.executor.apply("prod", [CreateGroupRole("g_test")])
        assert isinstance(failure.value.original, TargetUnavailable)
        assert "target prod unreachable" in str(failure.value)
        assert "PRIVATE_FRAGMENT" not in str(failure.value)


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize(
    "original",
    [
        psycopg.errors.QueryCanceled("PRIVATE"),
        psycopg.errors.LockNotAvailable("PRIVATE"),
        psycopg.errors.DeadlockDetected("PRIVATE"),
        psycopg.errors.InvalidPassword("PRIVATE"),
        psycopg.errors.ConnectionFailure("PRIVATE"),
        TargetUnavailable("prod", "credentials invalid", psycopg.errors.InvalidPassword("PRIVATE")),
        TargetUnavailable("prod", "secret missing or invalid", psycopg.ProgrammingError("PRIVATE")),
    ],
)
async def test_sync_last_error_preserves_safe_diagnostics_without_advancing_token(
    original: Exception, wrapped: bool, caplog: pytest.LogCaptureFixture
) -> None:
    db = await metadata.connect(":memory:")
    try:
        await metadata.migrate(db)
        async with metadata.transaction(db):
            await db.execute(
                "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
                "VALUES ('prod', 'h', 'd', 'ref')"
            )
        store = MemoryStore()
        await store.write([ids.group_tuple("test")])
        executor = AsyncMock()
        executor.apply.side_effect = ApplyError("prod", None, original) if wrapped else original
        syncer = Syncer(
            db,
            store,
            executor,
            ConnectionLocks(),
            fga_store_id="store",
            poll_interval_s=3600,
            full_reconcile=AsyncMock(),
        )
        await syncer.sync_once("prod")
        (status,) = await syncer.status()
        assert status["continuation_token"] is None and status["fail_count"] == 1
        error = status["last_error"]
        assert error is not None
        assert type(original).__name__ in error
        assert str(getattr(original, "sqlstate", None)) in error + caplog.text
        if isinstance(original, TargetUnavailable):
            assert original.error is not None
            assert original.reason in error and original.error in error
        assert "PRIVATE" not in error + caplog.text
        async with db.execute("SELECT error FROM audit_log WHERE kind = 'sync'") as cursor:
            assert await cursor.fetchone() == (error,)
    finally:
        await db.close()


async def test_unregistered_connection_is_not_reported_as_a_secret_problem() -> None:
    db = await metadata.connect(":memory:")
    try:
        await metadata.migrate(db)
        with pytest.raises(TargetUnavailable) as failure:
            await admin_connector(db)("missing")
        assert failure.value.reason == "connection not registered"
    finally:
        await db.close()


async def test_apply_failure_from_the_target_is_a_safe_502_and_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    original = psycopg.errors.InsufficientPrivilege("PRIVATE server text")
    response = await permission_error(Mock(spec=Request), ApplyError("prod", None, original))
    assert response.status_code == 502
    body = bytes(response.body).decode()
    assert "target prod apply failed" in body and "42501" in body
    assert "PRIVATE" not in body
    assert "apply on prod failed" in caplog.text and "PRIVATE" not in caplog.text
