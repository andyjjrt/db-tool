import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite


def to_iso(value: datetime) -> str:
    """Format an aware datetime as UTC with exactly three fractional digits."""
    if value.utcoffset() is None:
        raise ValueError("Metadata timestamps require a timezone-aware datetime")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now_iso() -> str:
    return to_iso(datetime.now(UTC))


@asynccontextmanager
async def transaction(conn: aiosqlite.Connection) -> AsyncIterator[None]:
    """Serialize writers on this connection; transactions must not be nested."""
    lock = getattr(conn, "_dbgw_transaction_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        conn.__dict__["_dbgw_transaction_lock"] = lock
    async with lock:
        try:
            await conn.execute("BEGIN IMMEDIATE")
            yield
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise


async def connect(path: str | Path) -> aiosqlite.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(path)
    try:
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute("PRAGMA recursive_triggers=ON")
    except BaseException:
        await conn.close()
        raise
    return conn


async def migrate(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version "
        "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL "
        "DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
        "CHECK (applied_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T"
        "[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'))"
    )
    await conn.commit()
    async with conn.execute("SELECT version FROM schema_version") as cursor:
        applied = {row[0] for row in await cursor.fetchall()}
    migrations = Path(__file__).parent / "migrations"
    for path in sorted(migrations.glob("*.sql"), key=lambda p: int(p.stem.split("_", 1)[0])):
        version = int(path.stem.split("_", 1)[0])
        if version in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        try:
            await conn.executescript("BEGIN IMMEDIATE;\n" + sql)
            await conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise
