"""Target connections as the Syncer, Reconciler and Provisioner see them.

Reads the SQLite ``connections`` table and turns it into what the permission
code needs: the ``MappingContext`` for the tuple mapping, and a factory that
opens an admin connection to one target by name (for ``PgExecutor`` and
``actual.read_actual``).

The admin credentials come from the secret named by ``admin_secret_ref``. The
secret is a libpq conninfo fragment holding only credentials, e.g.
``user=gw_admin password=...``; host, port, dbname and sslmode always come
from the connections row, so a secret cannot point the gateway at another
server.
"""

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import aiosqlite
import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from db_gateway.permissions.types import MappingContext
from db_gateway.secrets import SecretLookup, get_secret

# Keys a credentials secret may set; anything else is a ValueError.
SECRET_KEYS = frozenset({"user", "password", "passfile", "sslcert", "sslkey", "sslrootcert"})


class ConnectionLocks:
    """One asyncio.Lock per target connection, shared by everything that changes PG.

    Plan §2.7 point 5: the inline revoke, the Syncer and the Reconciler serialise
    on this lock per connection. Each holds it across a whole unit of work (the
    Syncer: apply one change and advance its token; the Reconciler: read tuples,
    read the catalog, apply the fixes), so one never applies a decision made
    from state the other has since changed. Lock order is always RuleService's
    global lock, then this lock, then PgExecutor's own lock. Build one instance
    per process and pass it to all of them.
    """

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    def __call__(self, connection: str) -> asyncio.Lock:
        return self._locks.setdefault(connection, asyncio.Lock())


@dataclass(frozen=True, slots=True)
class ConnectionInfo:
    id: int
    name: str
    host: str
    port: int
    dbname: str
    sslmode: str
    admin_secret_ref: str
    default_privilege_owners: tuple[str, ...]


async def load_connections(db: aiosqlite.Connection) -> list[ConnectionInfo]:
    """Every registered connection, ordered by id."""
    async with db.execute(
        "SELECT id, name, host, port, dbname, sslmode, admin_secret_ref, "
        "default_privilege_owners FROM connections ORDER BY id"
    ) as cur:
        rows = await cur.fetchall()
    return [
        ConnectionInfo(
            id=row[0],
            name=row[1],
            host=row[2],
            port=row[3],
            dbname=row[4],
            sslmode=row[5],
            admin_secret_ref=row[6],
            default_privilege_owners=tuple(json.loads(row[7])),
        )
        for row in rows
    ]


async def load_connection(db: aiosqlite.Connection, name: str) -> ConnectionInfo:
    """One connection by name; KeyError if it is not registered."""
    for info in await load_connections(db):
        if info.name == name:
            return info
    raise KeyError(f"connection is not registered: {name}")


def mapping_context(connections: list[ConnectionInfo]) -> MappingContext:
    return MappingContext(
        connections=[c.name for c in connections],
        default_privilege_owners={c.name: c.default_privilege_owners for c in connections},
    )


def admin_conninfo(info: ConnectionInfo, secrets: SecretLookup = get_secret) -> str:
    """The libpq conninfo for the connection's admin account."""
    credentials = conninfo_to_dict(secrets(info.admin_secret_ref))
    extra = set(credentials) - SECRET_KEYS
    if extra:
        raise ValueError(
            f"secret for connection {info.name!r} may only set {sorted(SECRET_KEYS)}, "
            f"not {sorted(extra)}"
        )
    if not credentials.get("user"):
        raise ValueError(f"secret for connection {info.name!r} must set user")
    return make_conninfo(
        "",
        **credentials,
        host=info.host,
        port=info.port,
        dbname=info.dbname,
        sslmode=info.sslmode,
        application_name="db-gateway",
    )


def admin_connector(
    db: aiosqlite.Connection, secrets: SecretLookup = get_secret
) -> Callable[[str], Awaitable[psycopg.AsyncConnection]]:
    """``connect(name)`` for PgExecutor: a fresh autocommit-off admin connection.

    Looks the connection up on every call, so connections registered later work.
    The caller owns and closes the returned connection.
    """

    async def connect(name: str) -> psycopg.AsyncConnection:
        info = await load_connection(db, name)
        return await psycopg.AsyncConnection.connect(admin_conninfo(info, secrets))

    return connect
