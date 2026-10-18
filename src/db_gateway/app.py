import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Collection
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import httpx
import psycopg
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from psycopg.sql import SQL, Identifier, Literal

from db_gateway.api import admin_users, auth_routes
from db_gateway.api.admin_permissions import router, validate_connection
from db_gateway.auth.oidc import OidcClient
from db_gateway.logging_config import install_access_log_filter
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
    oidc_client: OidcClient | None = None
    syncer: Syncer | None = None
    reconciler: Reconciler | None = None
    tasks: list[asyncio.Task[None]] = []
    checks: asyncio.Task[None] | None = None
    try:
        await migrate(conn)
        app.state.metadata = conn
        app.state.oidc = None
        if settings.oidc_issuer is not None:
            oidc_client = OidcClient.from_settings(
                settings,
                transport=app.state.oidc_transport,
                clock=app.state.oidc_clock,
            )
            app.state.oidc = oidc_client
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
                try:
                    if oidc_client is not None:
                        await oidc_client.aclose()
                finally:
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


_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _parse_origin(value: str, *, allow_path: bool) -> tuple[str, str, int] | None:
    """Normalize an http(s) origin to (scheme, host, effective port); None if malformed.

    ``Origin`` headers never carry a path, userinfo, query or fragment, so those
    are rejected for an incoming Origin; the configured redirect URI may have a
    path. Default ports are made explicit so ``https://gw`` and
    ``https://gw:443`` compare equal. Raw whitespace and control characters are
    rejected before parsing because ``urlsplit`` silently strips some of them;
    an explicitly empty port is rejected too.
    """
    if any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    ):
        return None
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.netloc:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        netloc = parts.netloc
        if netloc.startswith("["):
            _, _, remainder = netloc.partition("]")
            if remainder == ":":
                return None
        elif ":" in netloc and not netloc.rpartition(":")[2]:
            return None
        if not allow_path:
            if parts.query or parts.fragment:
                return None
            if parts.path not in ("", "/"):
                return None
        host = parts.hostname
        if not host:
            return None
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host.lower(), port


def _gateway_origin(redirect_uri: str | None) -> tuple[str, str, int] | None:
    """The gateway's own origin, derived from the configured redirect URI."""
    if not redirect_uri:
        return None
    return _parse_origin(redirect_uri, allow_path=True)


def create_app(
    settings: Settings | None = None,
    *,
    oidc_transport: httpx.AsyncBaseTransport | None = None,
    oidc_clock: Callable[[], float] | None = None,
) -> FastAPI:
    install_access_log_filter()
    app = FastAPI(lifespan=_lifespan)
    app.state.settings = settings if settings is not None else get_settings()
    app.state.oidc_transport = oidc_transport
    app.state.oidc_clock = oidc_clock
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
    app.include_router(admin_users.router)
    app.include_router(auth_routes.router)

    @app.middleware("http")
    async def reject_cross_origin_writes(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """SameSite=Lax plus an Origin check for unsafe requests to /api/ and logout."""
        path = request.url.path
        if request.method not in _SAFE_METHODS and (
            path.startswith("/api/") or path == "/auth/logout"
        ):
            origin = request.headers.get("origin")
            if origin is not None:
                allowed = _gateway_origin(request.app.state.settings.oidc_redirect_uri)
                parsed = _parse_origin(origin, allow_path=False)
                if parsed is None or parsed != allowed:
                    return JSONResponse(
                        status_code=403, content={"detail": "cross-origin request rejected"}
                    )
        return await call_next(request)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
