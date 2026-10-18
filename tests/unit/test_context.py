from collections.abc import AsyncIterator

import aiosqlite
import pytest
from psycopg.conninfo import conninfo_to_dict

from db_gateway import metadata
from db_gateway.permissions.context import (
    ConnectionLocks,
    admin_conninfo,
    load_connection,
    load_connections,
    mapping_context,
)


@pytest.fixture
async def db() -> AsyncIterator[aiosqlite.Connection]:
    conn = await metadata.connect(":memory:")
    try:
        await metadata.migrate(conn)
        async with metadata.transaction(conn):
            await conn.execute(
                "INSERT INTO connections (name, host, port, dbname, sslmode, admin_secret_ref, "
                "default_privilege_owners) VALUES ('prod', 'db.local', 6543, 'app', 'require', "
                "'prod-admin', '[\"app_owner\", \"etl\"]')"
            )
            await conn.execute(
                "INSERT INTO connections (name, host, dbname, admin_secret_ref) "
                "VALUES ('dev', 'dev.local', 'app', 'dev-admin')"
            )
        yield conn
    finally:
        await conn.close()


async def test_load_connections_and_mapping_context(db: aiosqlite.Connection) -> None:
    infos = await load_connections(db)
    assert [i.name for i in infos] == ["prod", "dev"]
    assert infos[0].default_privilege_owners == ("app_owner", "etl")
    assert infos[1].default_privilege_owners == ()
    ctx = mapping_context(infos)
    assert list(ctx.connections) == ["prod", "dev"]
    assert ctx.default_privilege_owners["prod"] == ("app_owner", "etl")
    assert (await load_connection(db, "dev")).host == "dev.local"
    with pytest.raises(KeyError):
        await load_connection(db, "nope")


async def test_admin_conninfo_takes_location_from_the_row(db: aiosqlite.Connection) -> None:
    info = await load_connection(db, "prod")

    def secrets(ref: str) -> str:
        return {"prod-admin": "user=gw_admin password='p w'"}[ref]

    parsed = conninfo_to_dict(admin_conninfo(info, secrets))
    assert parsed["user"] == "gw_admin"
    assert parsed["password"] == "p w"
    assert (parsed["host"], parsed["port"], parsed["dbname"], parsed["sslmode"]) == (
        "db.local",
        "6543",
        "app",
        "require",
    )


@pytest.mark.parametrize(
    "secret", ["user=a password=b host=evil", "password=b", "user=a dbname=other"]
)
async def test_admin_conninfo_rejects_bad_secrets(db: aiosqlite.Connection, secret: str) -> None:
    info = await load_connection(db, "prod")

    def secrets(ref: str) -> str:
        return secret

    with pytest.raises(ValueError):
        admin_conninfo(info, secrets)


def test_connection_locks_are_per_connection_and_stable() -> None:
    locks = ConnectionLocks()
    assert locks("prod") is locks("prod")
    assert locks("prod") is not locks("dev")
