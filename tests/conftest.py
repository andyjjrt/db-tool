"""Shared pytest fixtures for db-tool.

The integration tests in this repo talk to a Postgres+ParadeDB instance and
an OpenFGA server brought up by ``docker compose up -d --wait``. Connection
info comes from environment variables (see below); sensible defaults match
``docker-compose.yml``.

Concurrency contract
-------------------
Integration tests are serialised cluster-wide by a PostgreSQL session
advisory lock (see :func:`cluster_lock`). Every integration fixture that
touches the cluster (``target_db``, ``superuser_conn``, ``role_factory``,
``connect_as``, ``dbg_admin``, ``cluster_roles_cleanup``) takes this
lock as the first dependency, so a test cannot create cluster state
until the lock is acquired and cannot release it until teardown is done.
Because the lock is bound to the connection lifetime, closing the
connection releases the lock even if the test process is killed.

Fixed cluster-wide names used by these tests (``gw_managed``, etc.) are
safe to use because no two workers can run their integration bodies at
the same time. The lock is a no-op for unit tests.

Rules for new fixtures and tests:
  - Anything that creates cluster state (databases, roles) must be a
    function-scoped fixture depending on ``cluster_lock``, and only tests
    under tests/integration or tests/acceptance may use it (others fail).
  - The dev cluster belongs to the test suite: roles created by anything
    outside pytest while a test runs are reaped. Ad-hoc experiments must not
    run against it during test runs.
  - Waiting for the lock times out after DBGW_TEST_LOCK_TIMEOUT seconds
    (default 600); the failure names the process holding it.

Environment variables
---------------------
DBGW_TEST_PG_HOST       default 127.0.0.1
DBGW_TEST_PG_PORT       default 55432
DBGW_TEST_PG_USER       default postgres
DBGW_TEST_PG_PASSWORD   default postgres
DBGW_TEST_OPENFGA_URL   default http://127.0.0.1:58080

Skip behaviour
--------------
Tests under ``tests/integration/`` and ``tests/acceptance/`` are
auto-marked ``integration``. When at least one collected item needs the
integration services, we probe each one with a short timeout: ParadeDB is
considered reachable only if a real ``psycopg`` connection succeeds;
OpenFGA only if ``GET /healthz`` returns ``{"status": "SERVING"}``.
Otherwise those items are reported as skipped with a clear reason. Unit
runs do no network I/O at all.
"""

from __future__ import annotations

import os
import secrets
import string
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from socket import create_connection
from urllib.parse import urlparse

import httpx
import psycopg
import pytest
import pytest_asyncio
from psycopg.sql import SQL, Identifier, Literal

PG_HOST = os.environ.get("DBGW_TEST_PG_HOST", "127.0.0.1")
PG_PORT = int(os.environ.get("DBGW_TEST_PG_PORT", "55432"))
PG_USER = os.environ.get("DBGW_TEST_PG_USER", "postgres")
PG_PASSWORD = os.environ.get("DBGW_TEST_PG_PASSWORD", "postgres")
OPENFGA_URL = os.environ.get("DBGW_TEST_OPENFGA_URL", "http://127.0.0.1:58080")

# Postgres identifiers are capped at 63 bytes (NAMEDATALEN-1). Keep well
# below so callers can concatenate short suffixes (e.g. "g_<30>").
_MAX_NAME_LEN = 40
_SENTINEL_SUFFIX_LEN = 30

# A 64-bit constant for the cluster-wide integration test advisory lock.
# Any unique 64-bit int works; we pick something obviously derived from the
# project namespace so two projects don't accidentally serialise each other.
_INTEGRATION_LOCK_KEY = 0x4442_4757_4442_4757  # "DBGWDBGW"


@dataclass(frozen=True, slots=True)
class RoleInfo:
    """A created LOGIN role that can be used to open a real-password session."""

    name: str
    password: str


@dataclass(frozen=True, slots=True)
class DbgAdminInfo:
    """Bundle of roles for exercising the non-superuser privilege path.

    ``login`` is a CREATEROLE LOGIN role that tests can connect as.
    ``owner`` is the name of a NOLOGIN role that owns a schema created in
    ``target_db``; the role itself has no password and cannot be passed to
    ``connect_as``. ``login`` is a member of ``owner``, so
    ``SET ROLE owner`` works in the connection returned by :attr:`open`.
    """

    login: RoleInfo
    owner: str
    schema: str
    open: Callable[[], Awaitable[psycopg.AsyncConnection]]


def _random_suffix(length: int = _SENTINEL_SUFFIX_LEN) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _random_password(length: int = 20) -> str:
    # Avoid characters that need quoting or trip connection-string parsing.
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def _admin_conn(*, dbname: str | None = None) -> psycopg.AsyncConnection:
    """Open an autocommit connection as the superuser (for DDL only)."""
    return await psycopg.AsyncConnection.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        password=PG_PASSWORD,
        dbname=dbname or "postgres",
        autocommit=True,
    )


def _tcp_reachable(host: str, port: int, *, timeout: float = 0.5) -> bool:
    """Return True iff a TCP connection to host:port succeeds within ``timeout``."""
    try:
        with create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _paradedb_ready() -> bool:
    """ParadeDB is ready iff a real psycopg connection + query round-trip succeeds."""
    if not _tcp_reachable(PG_HOST, PG_PORT, timeout=0.5):
        return False
    try:
        with psycopg.Connection.connect(
            host=PG_HOST,
            port=PG_PORT,
            user=PG_USER,
            password=PG_PASSWORD,
            dbname="postgres",
            connect_timeout=2,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return True
    except Exception:
        return False


def _openfga_ready() -> bool:
    """OpenFGA is ready iff /healthz returns HTTP 200 with status == SERVING."""
    parsed = urlparse(OPENFGA_URL)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not _tcp_reachable(host, port, timeout=0.5):
        return False
    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(f"{OPENFGA_URL.rstrip('/')}/healthz")
        if resp.status_code != 200:
            return False
        return resp.json().get("status") == "SERVING"
    except Exception:
        return False


def _missing_services() -> list[str]:
    missing: list[str] = []
    if not _paradedb_ready():
        missing.append(f"ParadeDB at {PG_HOST}:{PG_PORT}")
    if not _openfga_ready():
        missing.append(f"OpenFGA at {OPENFGA_URL}")
    return missing


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-mark integration tests, then skip them if services are down.

    Probes run only when at least one collected item needs the integration
    services; unit-only runs do no network I/O. Paths outside ``rootpath``
    are skipped silently.
    """
    for item in items:
        try:
            rel = item.path.relative_to(config.rootpath)
        except ValueError:
            continue
        if {"integration", "acceptance"} & set(rel.parts):
            item.add_marker(pytest.mark.integration)

    if not any("integration" in item.keywords for item in items):
        return

    missing = _missing_services()
    if not missing:
        return
    reason = f"integration services unreachable: {', '.join(missing)}"
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(pytest.mark.skip(reason=reason))


@pytest.fixture
def unique_name() -> Callable[[str], str]:
    """Return a callable that yields a fresh lowercase ``<prefix>_<rand>`` name.

    Names are at most :data:`_MAX_NAME_LEN` characters and consist only of
    ``[a-z0-9_]`` so they round-trip through Postgres identifiers. The
    randomness is enough to keep cluster-wide names unique across
    sequential tests in the same run.
    """

    def _make(prefix: str) -> str:
        # Truncate the prefix defensively so callers can't blow past the cap.
        safe_prefix = prefix[: _MAX_NAME_LEN - 1 - _SENTINEL_SUFFIX_LEN]
        return f"{safe_prefix}_{_random_suffix(_SENTINEL_SUFFIX_LEN)}"[:_MAX_NAME_LEN]

    return _make


@pytest_asyncio.fixture
async def cluster_lock(
    request: pytest.FixtureRequest,
) -> AsyncIterator[psycopg.AsyncConnection | None]:
    """Cluster-wide PG advisory lock, scoped to one integration test.

    Holds :data:`_INTEGRATION_LOCK_KEY` for the lifetime of the yielded
    connection. Every integration fixture depends on this so the cluster is
    fully serialised across processes: ``pg_advisory_lock`` blocks until
    any other worker that holds the key releases it. For non-integration
    tests the fixture is a no-op (yields ``None``), so unit runs do no
    network I/O.
    """
    if "integration" not in request.keywords:
        cluster = {"target_db", "superuser_conn", "role_factory", "connect_as", "dbg_admin"}
        if cluster & set(request.fixturenames):
            pytest.fail("cluster fixtures need a test under tests/integration or tests/acceptance")
        yield None
        return

    conn = await psycopg.AsyncConnection.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        password=PG_PASSWORD,
        dbname="postgres",
        autocommit=True,
        application_name=f"dbgw-tests-{os.getpid()}",
    )
    try:
        timeout_s = int(os.environ.get("DBGW_TEST_LOCK_TIMEOUT", "600"))
        async with conn.cursor() as cur:
            await cur.execute(SQL("SET lock_timeout = {}").format(Literal(f"{timeout_s}s")))
            try:
                await cur.execute("SELECT pg_advisory_lock(%s)", (_INTEGRATION_LOCK_KEY,))
            except psycopg.errors.LockNotAvailable:
                await cur.execute(
                    "SELECT a.pid, a.application_name, a.backend_start"
                    " FROM pg_locks l JOIN pg_stat_activity a USING (pid)"
                    " WHERE l.locktype = 'advisory' AND l.granted"
                )
                holders = await cur.fetchall()
                pytest.fail(f"waited {timeout_s}s for the integration test lock; held by {holders}")
            await cur.execute("SET lock_timeout = 0")
        yield conn
    finally:
        try:
            async with conn.cursor() as cur:
                await cur.execute("SELECT pg_advisory_unlock(%s)", (_INTEGRATION_LOCK_KEY,))
        except Exception:  # noqa: BLE001
            pass
        await conn.close()


@pytest_asyncio.fixture
async def target_db(
    cluster_lock: psycopg.AsyncConnection | None,
) -> AsyncIterator[str]:
    """Yield the name of a fresh database, dropping it after the test.

    The db is created with the ``pg_search`` extension enabled so callers can
    use ParadeDB features immediately. If ``CREATE EXTENSION`` fails, the
    database is still dropped in the finally clause.
    """
    name = f"t_{_random_suffix()}"
    async with await _admin_conn() as admin:
        await admin.execute(SQL("CREATE DATABASE {}").format(Identifier(name)))
    try:
        async with await _admin_conn(dbname=name) as setup:
            await setup.execute("CREATE EXTENSION IF NOT EXISTS pg_search")
        yield name
    finally:
        errors: list[Exception] = []
        try:
            async with await _admin_conn() as drop_admin:
                await drop_admin.execute(
                    SQL("DROP DATABASE {} WITH (FORCE)").format(Identifier(name))
                )
        except Exception as exc:  # noqa: BLE001 — best-effort cleanup
            errors.append(exc)
        if errors:
            raise RuntimeError(
                f"target_db teardown failed for {name!r}: " + "; ".join(str(e) for e in errors)
            ) from errors[0]


@pytest_asyncio.fixture
async def superuser_conn(
    target_db: str,
    cluster_lock: psycopg.AsyncConnection | None,
) -> AsyncIterator[psycopg.AsyncConnection]:
    """Yield an autocommit superuser connection into ``target_db``."""
    conn = await _admin_conn(dbname=target_db)
    try:
        yield conn
    finally:
        await conn.close()


@pytest_asyncio.fixture
async def role_factory(
    target_db: str,
    superuser_conn: psycopg.AsyncConnection,
    cluster_lock: psycopg.AsyncConnection | None,
) -> AsyncIterator[Callable[[str], Awaitable[RoleInfo]]]:
    """Yield a factory that creates LOGIN roles and tears them down on exit.

    Roles are cluster-wide, so the per-call suffix is what guarantees
    uniqueness across tests in the same cluster. Teardown is failure-safe:
    one bad ``DROP OWNED`` / ``DROP ROLE`` does not stop the rest; errors
    are aggregated and re-raised as a single ``RuntimeError``.
    """
    created: list[RoleInfo] = []

    async def _make(prefix: str) -> RoleInfo:
        info = RoleInfo(name=f"{prefix}_{_random_suffix()}", password=_random_password())
        async with superuser_conn.cursor() as cur:
            # CREATE ROLE ... PASSWORD does not accept query parameters (the
            # grammar only accepts a string literal), so the password must be
            # inlined. The password is generated by us from [A-Za-z0-9] only,
            # so no escaping is needed.
            stmt = SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                Identifier(info.name), Literal(info.password)
            )
            await cur.execute(stmt)
        created.append(info)
        return info

    try:
        yield _make
    finally:
        errors: list[Exception] = []
        # DROP OWNED must run while connected to the database that owns the objects.
        try:
            async with await _admin_conn(dbname=target_db) as owned:
                async with owned.cursor() as cur:
                    for info in created:
                        try:
                            await cur.execute(
                                SQL("DROP OWNED BY {} CASCADE").format(Identifier(info.name))
                            )
                        except Exception as exc:  # noqa: BLE001
                            errors.append(exc)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        # DROP ROLE is cluster-wide.
        try:
            async with superuser_conn.cursor() as cur:
                for info in created:
                    try:
                        await cur.execute(
                            SQL("DROP ROLE IF EXISTS {}").format(Identifier(info.name))
                        )
                    except Exception as exc:  # noqa: BLE001
                        errors.append(exc)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        if errors:
            raise RuntimeError(
                f"role_factory teardown had {len(errors)} error(s): "
                + "; ".join(str(e) for e in errors)
            ) from errors[0]


@pytest_asyncio.fixture
async def connect_as(
    target_db: str,
    cluster_lock: psycopg.AsyncConnection | None,
) -> AsyncIterator[Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]]]:
    """Yield a coroutine that opens a real-password session into ``target_db``.

    Every connection the factory returns is tracked and closed at teardown
    (failure-safe; one bad close does not stop the others).
    """
    opened: list[psycopg.AsyncConnection] = []

    async def _open(role: RoleInfo) -> psycopg.AsyncConnection:
        conn = await psycopg.AsyncConnection.connect(
            host=PG_HOST,
            port=PG_PORT,
            user=role.name,
            password=role.password,
            dbname=target_db,
            autocommit=True,
        )
        opened.append(conn)
        return conn

    try:
        yield _open
    finally:
        errors: list[Exception] = []
        for conn in opened:
            try:
                await conn.close()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        if errors:
            raise RuntimeError(
                f"connect_as teardown had {len(errors)} error(s): "
                + "; ".join(str(e) for e in errors)
            ) from errors[0]


@pytest_asyncio.fixture
async def dbg_admin(
    target_db: str,
    superuser_conn: psycopg.AsyncConnection,
    unique_name: Callable[[str], str],
    cluster_lock: psycopg.AsyncConnection | None,
) -> AsyncIterator[DbgAdminInfo]:
    """Yield a CREATEROLE LOGIN role + a NOLOGIN owner role for the non-super path.

    Setup creates (in ``target_db``):

    * a LOGIN ``dbg`` role with ``CREATEROLE`` and a random password,
    * a NOLOGIN ``own`` role that owns a fresh schema,
    * ``GRANT own TO dbg`` so ``SET ROLE own`` works.

    ``own`` deliberately lacks ``CREATEROLE``: production roles that own
    a schema do not, and an integration test that wants to ``CREATE ROLE``
    while sitting in the owner must ``RESET ROLE`` first. The
    :func:`test_dbg_admin_can_create_role_only_as_self` test pins that
    contract.

    Roles and the schema they own are reaped by :func:`cluster_roles_cleanup`.
    """
    dbg_name = unique_name("dbg")
    dbg_password = _random_password()
    owner_name = unique_name("own")
    schema_name = unique_name("s")

    async with superuser_conn.cursor() as cur:
        await cur.execute(
            SQL("CREATE ROLE {} LOGIN CREATEROLE PASSWORD {}").format(
                Identifier(dbg_name), Literal(dbg_password)
            )
        )
        await cur.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(owner_name)))
        await cur.execute(
            SQL("GRANT {} TO {}").format(Identifier(owner_name), Identifier(dbg_name))
        )
        await cur.execute(
            SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(
                Identifier(schema_name), Identifier(owner_name)
            )
        )

    async def _open() -> psycopg.AsyncConnection:
        return await psycopg.AsyncConnection.connect(
            host=PG_HOST,
            port=PG_PORT,
            user=dbg_name,
            password=dbg_password,
            dbname=target_db,
            autocommit=True,
        )

    try:
        yield DbgAdminInfo(
            login=RoleInfo(dbg_name, dbg_password),
            owner=owner_name,
            schema=schema_name,
            open=_open,
        )
    finally:
        # Roles and schema are cleaned up by ``cluster_roles_cleanup``.
        pass


@pytest.fixture(scope="session")
def openfga_url() -> str:
    """Session-scoped OpenFGA HTTP base URL."""
    return OPENFGA_URL


@pytest_asyncio.fixture
async def fga_store(openfga_url: str) -> AsyncIterator[str]:
    """Create a fresh OpenFGA store via HTTP and delete it after the test."""
    # OpenFGA requires a Name that matches ^[a-zA-Z0-9\s\.\-\/^_&@]{3,64}$.
    name = f"test-{_random_suffix(8)}"
    async with httpx.AsyncClient(base_url=openfga_url, timeout=10.0) as client:
        resp = await client.post("/stores", json={"name": name})
        resp.raise_for_status()
        store_id = resp.json()["id"]
        assert isinstance(store_id, str) and store_id, "OpenFGA must return a store id"
    try:
        yield store_id
    finally:
        async with httpx.AsyncClient(base_url=openfga_url, timeout=10.0) as client:
            # 404 on the second delete is fine; the goal is just to clean up.
            await client.delete(f"/stores/{store_id}")


@pytest_asyncio.fixture(autouse=True)
async def cluster_roles_cleanup(
    request: pytest.FixtureRequest,
    cluster_lock: psycopg.AsyncConnection | None,
) -> AsyncIterator[None]:
    """Snapshot ``pg_roles`` around integration tests and reap new ones.

    Active only for tests with the ``integration`` marker, so unit tests
    never touch the network or the cluster. Depends on :func:`cluster_lock`
    so the before snapshot is captured *with the lock held* — nothing the
    test does can race in between the snapshot and the test body. The
    after snapshot is taken in ``finally`` while the lock is still held.
    """
    if "integration" not in request.keywords:
        yield
        return

    async def _snapshot() -> set[str]:
        async with await _admin_conn() as admin:
            async with admin.cursor() as cur:
                await cur.execute("SELECT rolname FROM pg_roles")
                return {row[0] for row in await cur.fetchall()}

    before = await _snapshot()
    try:
        yield
    finally:
        after = await _snapshot()
        new_roles = after - before
        if new_roles:
            await _reap_new_roles(new_roles)


async def _reap_new_roles(new_roles: set[str]) -> None:
    """Best-effort cluster-wide cleanup of every new role.

    The per-role try/except loop lets one bad terminate / ``DROP OWNED`` /
    ``DROP ROLE`` not stop the rest. Errors are annotated with the
    offending role's name so callers can verify the aggregated message.
    A failure to list user databases is recorded as an error rather than
    silently downgrading to an empty list.
    """
    errors: list[Exception] = []
    databases: list[str] = []
    try:
        async with await _admin_conn() as admin:
            async with admin.cursor() as cur:
                await cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
                databases = [row[0] for row in await cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        errors.append(RuntimeError(f"listing pg_database: {exc}"))

    for role_name in new_roles:
        # 1. Terminate the role's existing backends (in any database).
        try:
            async with await _admin_conn() as admin:
                async with admin.cursor() as cur:
                    await cur.execute(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = %s",
                        (role_name,),
                    )
        except Exception as exc:  # noqa: BLE001
            errors.append(RuntimeError(f"role {role_name} pg_terminate_backend: {exc}"))
        # 2. DROP OWNED BY ... CASCADE in every user database (best effort).
        for dbname in databases:
            try:
                async with await _admin_conn(dbname=dbname) as admin:
                    async with admin.cursor() as cur:
                        await cur.execute(
                            SQL("DROP OWNED BY {} CASCADE").format(Identifier(role_name))
                        )
            except Exception as exc:  # noqa: BLE001
                errors.append(RuntimeError(f"role {role_name} DROP OWNED in {dbname}: {exc}"))
        # 3. DROP ROLE itself (cluster-wide).
        try:
            async with await _admin_conn() as admin:
                async with admin.cursor() as cur:
                    await cur.execute(SQL("DROP ROLE IF EXISTS {}").format(Identifier(role_name)))
        except Exception as exc:  # noqa: BLE001
            errors.append(RuntimeError(f"role {role_name} DROP ROLE: {exc}"))
    if errors:
        raise RuntimeError(
            f"cluster_roles_cleanup reaped {len(errors)} error(s): "
            + "; ".join(str(e) for e in errors)
        ) from errors[0]
