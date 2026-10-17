"""Integration smoke tests for the docker-compose dev stack.

These tests exercise the fixtures in ``tests/conftest.py`` and the
``docker-compose.yml`` contract. They are skipped automatically when the
backends are unreachable (see ``pytest_collection_modifyitems``). The
``cluster_lock`` advisory lock in ``conftest`` makes integration runs
serialised cluster-wide, so the parallel processes that the brief asks
for can run side-by-side without colliding on ``gw_managed`` or any
other fixed cluster-wide name.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from tests import conftest
from tests.conftest import (
    PG_HOST,
    PG_PASSWORD,
    PG_PORT,
    PG_USER,
    DbgAdminInfo,
    RoleInfo,
)

pytestmark = pytest.mark.integration


async def test_target_db_exists_and_pg_search_loads(
    target_db: str, superuser_conn: psycopg.AsyncConnection
) -> None:
    """The freshly created db is reachable and pg_search can be (re-)enabled."""
    async with superuser_conn.cursor() as cur:
        await cur.execute("CREATE EXTENSION IF NOT EXISTS pg_search")
        await cur.execute("SHOW shared_preload_libraries")
        row = await cur.fetchone()
        assert row is not None
        preload = row[0]
    assert "pg_search" in preload, preload
    async with superuser_conn.cursor() as cur:
        await cur.execute("SELECT current_database()")
        row = await cur.fetchone()
        assert row is not None
        dbname = row[0]
    assert dbname == target_db


async def test_role_factory_and_connect_as(
    target_db: str,
    superuser_conn: psycopg.AsyncConnection,
    role_factory: Callable[[str], Awaitable[RoleInfo]],
    connect_as: Callable[[RoleInfo], Awaitable[psycopg.AsyncConnection]],
) -> None:
    """A role created via ``role_factory`` can log in via ``connect_as``."""
    role = await role_factory("u")

    async with await connect_as(role) as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT session_user")
            row = await cur.fetchone()
            assert row is not None
            session_user = row[0]

    assert session_user == role.name


async def test_openfga_healthz_serving(openfga_url: str) -> None:
    """OpenFGA ``/healthz`` reports SERVING (the readiness the gRPC probe mirrors)."""
    async with httpx.AsyncClient(base_url=openfga_url, timeout=5.0) as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200, resp.text
    assert resp.json().get("status") == "SERVING"


async def test_fga_store_round_trip(openfga_url: str, fga_store: str) -> None:
    """The created store id is retrievable via the HTTP API."""
    async with httpx.AsyncClient(base_url=openfga_url, timeout=10.0) as client:
        resp = await client.get(f"/stores/{fga_store}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("id") == fga_store


async def test_paradedb_settings_report_pg_search() -> None:
    """Sanity-check the server-level setting outside the test db.

    Protects against accidentally swapping the ParadeDB image for stock
    PostgreSQL in a future change.
    """
    conn = await psycopg.AsyncConnection.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        password=PG_PASSWORD,
        dbname="postgres",
        autocommit=True,
    )
    try:
        async with conn.cursor() as cur:
            await cur.execute("SHOW shared_preload_libraries")
            row = await cur.fetchone()
            assert row is not None
            preload = row[0]
    finally:
        await conn.close()
    assert "pg_search" in preload


async def test_unique_name_is_lowercase_and_short(unique_name: Callable[[str], str]) -> None:
    """``unique_name`` produces lowercase <=40 char identifiers that don't repeat."""
    a = unique_name("g")
    b = unique_name("g")
    assert a != b, "two consecutive calls must differ"
    assert a.replace("_", "").isalnum() and a.islower()
    assert len(a) <= 40


def _patch_cursor_execute(
    monkeypatch: pytest.MonkeyPatch,
    predicate: Callable[[str], bool],
    exc_factory: Callable[[str], Exception],
) -> None:
    """Patch ``psycopg.AsyncCursor.execute`` to raise when ``predicate(sql)`` is true.

    The wrapper captures the original execute and delegates to it on the
    fall-through path. ``monkeypatch.undo()`` should be called by the test
    body before any further cluster state work that needs a clean execute.
    """
    real_execute = psycopg.AsyncCursor.execute

    async def patched(self: psycopg.AsyncCursor, query: Any, *args: Any, **kwargs: Any) -> Any:
        sql_text = str(query)
        if predicate(sql_text):
            raise exc_factory(sql_text)
        return await real_execute(self, query, *args, **kwargs)

    monkeypatch.setattr(psycopg.AsyncCursor, "execute", patched)


async def test_reap_new_roles_continues_after_one_failure(
    target_db: str,
    superuser_conn: psycopg.AsyncConnection,
    unique_name: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_reap_new_roles`` keeps going when one role's drop raises.

    Three roles are created. The cursor's ``execute`` is patched so DROP
    ROLE for one specific name raises. The reap loop must still drop the
    other two, and the aggregated ``RuntimeError`` must mention the bad
    role's name. After the call we restore the original execute and drop
    the surviving role by hand.
    """
    good_a = unique_name("cl")
    bad = unique_name("cl")
    good_b = unique_name("cl")

    async with superuser_conn.cursor() as cur:
        for name in (good_a, bad, good_b):
            await cur.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(name)))

    def _pred(sql_text: str) -> bool:
        return bad in sql_text and "DROP ROLE" in sql_text

    def _exc(sql_text: str) -> Exception:
        return psycopg.Error(f"simulated: cannot DROP ROLE {bad}")

    _patch_cursor_execute(monkeypatch, _pred, _exc)

    try:
        with pytest.raises(RuntimeError, match="cluster_roles_cleanup reaped") as excinfo:
            await conftest._reap_new_roles({good_a, bad, good_b})

        # The aggregated message names the bad role.
        assert bad in str(excinfo.value), str(excinfo.value)
    finally:
        monkeypatch.undo()

    # Two "good" roles are gone; bad may survive (its drop was blocked).
    async with superuser_conn.cursor() as cur:
        await cur.execute(
            "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)",
            ([good_a, good_b],),
        )
        rows = await cur.fetchall()
    assert rows == [], f"good roles leaked past cleanup: {rows!r}"
    async with superuser_conn.cursor() as cur:
        await cur.execute(SQL("DROP ROLE IF EXISTS {}").format(Identifier(bad)))


async def test_reap_new_roles_succeeds_when_all_droppable(
    target_db: str,
    superuser_conn: psycopg.AsyncConnection,
    unique_name: Callable[[str], str],
) -> None:
    """``_reap_new_roles`` returns cleanly when every role is droppable."""
    names = [unique_name("cl") for _ in range(3)]
    async with superuser_conn.cursor() as cur:
        for name in names:
            await cur.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(name)))
    await conftest._reap_new_roles(set(names))
    async with superuser_conn.cursor() as cur:
        await cur.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (names,))
        rows = await cur.fetchall()
    assert rows == [], f"roles leaked: {rows!r}"


async def test_reap_new_roles_records_db_listing_failure(
    target_db: str,
    superuser_conn: psycopg.AsyncConnection,
    unique_name: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the database listing query fails, the error is surfaced (not swallowed)."""
    name = unique_name("cl")
    async with superuser_conn.cursor() as cur:
        await cur.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(name)))

    def _pred(sql_text: str) -> bool:
        return "pg_database" in sql_text and "datistemplate" in sql_text

    def _exc(sql_text: str) -> Exception:
        return psycopg.Error("simulated: pg_database listing failed")

    _patch_cursor_execute(monkeypatch, _pred, _exc)

    try:
        with pytest.raises(RuntimeError, match="listing pg_database"):
            await conftest._reap_new_roles({name})
    finally:
        monkeypatch.undo()

    async with superuser_conn.cursor() as cur:
        await cur.execute(SQL("DROP ROLE IF EXISTS {}").format(Identifier(name)))


async def test_dbg_admin_owner_has_no_password(dbg_admin: DbgAdminInfo) -> None:
    """``DbgAdminInfo.owner`` is just the role name (no password to misuse)."""
    assert isinstance(dbg_admin.owner, str)
    assert dbg_admin.owner


async def test_dbg_admin_can_create_role_only_as_self(
    target_db: str, dbg_admin: DbgAdminInfo, unique_name: Callable[[str], str]
) -> None:
    """``dbg_admin`` can CREATE ROLE; the owner role cannot (production parity)."""
    child = unique_name("child")
    async with await dbg_admin.open() as conn:
        async with conn.cursor() as cur:
            # As dbg_admin (CREATEROLE): success.
            await cur.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(child)))
            await cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (child,))
            row = await cur.fetchone()
            assert row is not None, "dbg_admin should be able to CREATE ROLE"
            # After SET ROLE owner (NOLOGIN, no CREATEROLE): failure.
            await cur.execute(SQL("SET ROLE {}").format(Identifier(dbg_admin.owner)))
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                await cur.execute(
                    SQL("CREATE ROLE {} NOLOGIN").format(Identifier(child + "_again"))
                )
            await cur.execute("RESET ROLE")
        await conn.close()
    # Tidy up the child role we created.
    conn = await psycopg.AsyncConnection.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        password=PG_PASSWORD,
        dbname=target_db,
        autocommit=True,
    )
    try:
        async with conn.cursor() as cur:
            await cur.execute(SQL("DROP ROLE IF EXISTS {}").format(Identifier(child)))
    finally:
        await conn.close()


async def test_gw_managed_round_trip_even_if_already_exists(
    superuser_conn: psycopg.AsyncConnection,
) -> None:
    """A test that recreates a fixed-name role is safe even if it already exists.

    The DROP ROLE IF EXISTS at the start of the test makes the test pass
    regardless of whether ``gw_managed`` was left over from a previous
    run. The re-create shows the test itself is idempotent.
    """
    async with superuser_conn.cursor() as cur:
        await cur.execute("DROP ROLE IF EXISTS gw_managed")
        await cur.execute("CREATE ROLE gw_managed NOLOGIN")
    async with superuser_conn.cursor() as cur:
        await cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'gw_managed'")
        row = await cur.fetchone()
        assert row is not None
    # cluster_roles_cleanup reaps it on the way out.
