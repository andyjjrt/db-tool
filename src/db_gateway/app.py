import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Collection
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg.sql import SQL, Identifier, Literal

from db_gateway.api.admin_permissions import router, validate_connection
from db_gateway.metadata import connect, migrate
from db_gateway.permissions import admin, scan
from db_gateway.permissions.admin import AdminForbidden
from db_gateway.permissions.context import (
    ConnectionLocks,
    TargetQueryFailed,
    admin_connector,
    load_connections,
    safe_error,
)
from db_gateway.permissions.executor import ApplyError, PgExecutor
from db_gateway.permissions.ids import InvalidInput
from db_gateway.permissions.reconciler import Reconciler
from db_gateway.permissions.rules import NotFound, RuleConflict, RuleService, TargetUnavailable
from db_gateway.permissions.scan import UnsafeView
from db_gateway.permissions.store import PermissionStoreUnavailable
from db_gateway.permissions.store_openfga import OpenFgaStore
from db_gateway.permissions.syncer import Syncer
from db_gateway.settings import Settings, get_settings

logger = logging.getLogger(__name__)


class TargetScanner:
    def __init__(self, connector: Callable[[str], Awaitable[psycopg.AsyncConnection]]) -> None:
        self._connect = connector

    async def unsafe_views(
        self, connection: str, tables: Collection[tuple[str, str]]
    ) -> list[UnsafeView]:
        conn = await self._connect(connection)
        try:
            async with conn:
                return await scan.unsafe_views(conn, tables)
        except psycopg.OperationalError as exc:
            raise TargetQueryFailed(connection, exc) from None


class TargetPartitionStats:
    def __init__(self, connector: Callable[[str], Awaitable[psycopg.AsyncConnection]]) -> None:
        self._connect = connector

    async def distinct_count(
        self, connection: str, schema: str, table: str, column: str, limit: int
    ) -> int:
        conn = await self._connect(connection)
        try:
            async with conn:
                cursor = await conn.execute(
                    SQL(
                        "SELECT count(*) FROM (SELECT DISTINCT {} FROM {} LIMIT {}) AS vals"
                    ).format(Identifier(column), Identifier(schema, table), Literal(limit + 1))
                )
                row = await cursor.fetchone()
                assert row is not None
                return row[0]
        except psycopg.errors.UndefinedTable as exc:
            raise NotFound(f"table not found: {schema}.{table}") from exc
        except psycopg.errors.UndefinedColumn as exc:
            raise InvalidInput(f"column not found: {column}") from exc
        except psycopg.errors.UndefinedFunction as exc:
            raise InvalidInput(
                f"column {column} cannot be used for row control: no equality operator"
            ) from exc
        except psycopg.OperationalError as exc:
            raise TargetQueryFailed(connection, exc) from None


async def _check_connections(app: FastAPI) -> None:
    for info in await load_connections(app.state.metadata):
        problems = await validate_connection(info)
        if problems:
            logger.warning("Target setup problems on %s: %s", info.name, problems)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = app.state.settings
    conn = await connect(settings.metadata_db_path)
    store: OpenFgaStore | None = None
    syncer: Syncer | None = None
    reconciler: Reconciler | None = None
    tasks: list[asyncio.Task[None]] = []
    checks: asyncio.Task[None] | None = None
    try:
        await migrate(conn)
        app.state.metadata = conn
        app.state.store = None
        app.state.store_ready = False
        app.state.store_model_lock = asyncio.Lock()
        if not admin.INITIAL_ADMINS:
            logger.warning("INITIAL_ADMINS is empty; no initial administrator can remove admins")
        if settings.openfga_store_id is not None:
            store = OpenFgaStore.from_settings(settings)
            app.state.store = store
            try:
                await store.ensure_model()
                app.state.store_ready = True
            except PermissionStoreUnavailable:
                logger.warning("OpenFGA unavailable at startup; admin API will return 503")
            locks = ConnectionLocks()
            connector = admin_connector(conn, connect_timeout_s=settings.target_connect_timeout_s)
            executor = PgExecutor(connector)
            reconciler = Reconciler(conn, store, executor, connector, locks)
            syncer = Syncer(
                conn,
                store,
                executor,
                locks,
                fga_store_id=settings.openfga_store_id,
                poll_interval_s=settings.sync_poll_interval_s,
                full_reconcile=reconciler.reconcile_strict,
            )
            app.state.locks = locks
            app.state.executor = executor
            app.state.syncer = syncer
            app.state.reconciler = reconciler
            app.state.rules = RuleService(
                conn,
                store,
                executor,
                TargetPartitionStats(connector),
                inline=syncer,
                locks=locks,
                scanner=TargetScanner(connector),
                revoke_timeout_s=settings.revoke_sync_timeout_s,
            )
            checks = asyncio.create_task(_check_connections(app), name="target-checks")
            tasks = [
                asyncio.create_task(syncer.run(), name="permission-sync"),
                asyncio.create_task(
                    reconciler.run_periodic(settings.reconcile_interval_s),
                    name="permission-reconcile",
                ),
                checks,
            ]
        else:
            logger.warning("openfga_store_id is not configured; admin API will return 503")
        app.state.permission_tasks = tasks
        yield
    finally:
        try:
            if checks is not None:
                checks.cancel()
            if reconciler is not None:
                reconciler.stop()
            if syncer is not None:
                await syncer.stop()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for task, result in zip(tasks, results, strict=True):
                if isinstance(result, BaseException) and not isinstance(
                    result, asyncio.CancelledError
                ):
                    logger.error("Background task %s failed: %s", task.get_name(), result)
        finally:
            try:
                if store is not None:
                    await store.aclose()
            finally:
                await conn.close()


async def permission_error(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, ApplyError):
        if isinstance(exc.original, TargetUnavailable):
            exc = exc.original
        elif isinstance(exc.original, psycopg.OperationalError):
            exc = TargetQueryFailed(exc.connection, exc.original)
        else:
            logger.error("apply on %s failed: %s", exc.connection, safe_error(exc))
            original = exc.original
            if isinstance(original, psycopg.Error):
                # e.g. the admin account lacks a privilege (plan §9): reported, never fixed
                return JSONResponse(
                    status_code=502,
                    content={
                        "detail": f"target {exc.connection} apply failed",
                        "sqlstate": original.sqlstate,
                        "error": type(original).__name__,
                    },
                )
            return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
    status = {
        RuleConflict: 409,
        NotFound: 404,
        InvalidInput: 422,
        AdminForbidden: 403,
        PermissionStoreUnavailable: 503,
        TargetUnavailable: 503,
        TargetQueryFailed: 503,
    }
    code = next(value for kind, value in status.items() if isinstance(exc, kind))
    content: dict[str, object] = {"detail": str(exc)}
    if isinstance(exc, RuleConflict):
        content["conflicts"] = exc.conflicts or [{"message": str(exc)}]
    if isinstance(exc, TargetUnavailable):
        logger.warning("%s", exc)
    if isinstance(exc, TargetQueryFailed):
        content.update(sqlstate=exc.sqlstate, error=exc.error)
    return JSONResponse(status_code=code, content=content)


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(lifespan=_lifespan)
    app.state.settings = settings if settings is not None else get_settings()
    for kind in (
        RuleConflict,
        NotFound,
        InvalidInput,
        AdminForbidden,
        PermissionStoreUnavailable,
        TargetUnavailable,
        TargetQueryFailed,
        ApplyError,
    ):
        app.add_exception_handler(kind, permission_error)
    app.include_router(router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
