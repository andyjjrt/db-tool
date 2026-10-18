"""Typed data access for the ``users`` table.

Pure SQL helpers with no FastAPI imports: the admin API composes them inside
one :func:`db_gateway.metadata.transaction` so a row change and its ``admin``
audit row commit together, and the login flow can reuse the read helpers.
``login_key`` is the OIDC login claim value, stored stripped and
case-sensitive; ``INITIAL_ADMINS`` matches it, not ``users.id``. ``oidc_sub`` is
the OIDC subject an account is bound to; :func:`unbind` clears it.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import aiosqlite

from db_gateway.metadata import now_iso

# Every column, in table order (oidc_sub is the bound OIDC subject).
_COLUMNS = (
    "id, login_key, email, display_name, pg_role_name, disabled_at, last_oidc_sub, oidc_sub,"
    " created_at"
)

# The columns update() may set. id and created_at are fixed; pg_role_name and
# last_oidc_sub belong to other flows (provisioner, OIDC login) and oidc_sub to
# the login binding -- unbind() clears it explicitly, PATCH must not touch it.
_EDITABLE = frozenset({"login_key", "email", "display_name"})


@dataclass(frozen=True, slots=True)
class UserRow:
    """One row of ``users``."""

    id: int
    login_key: str
    email: str | None
    display_name: str | None
    pg_role_name: str | None
    disabled_at: str | None
    last_oidc_sub: str | None
    oidc_sub: str | None
    created_at: str


def _row(values: Sequence[Any]) -> UserRow:
    return UserRow(*values)


async def get_by_id(conn: aiosqlite.Connection, user_id: int) -> UserRow | None:
    async with conn.execute(f"SELECT {_COLUMNS} FROM users WHERE id = ?", (user_id,)) as cur:
        row = await cur.fetchone()
    return None if row is None else _row(row)


async def get_by_login_key(conn: aiosqlite.Connection, login_key: str) -> UserRow | None:
    async with conn.execute(
        f"SELECT {_COLUMNS} FROM users WHERE login_key = ?", (login_key,)
    ) as cur:
        row = await cur.fetchone()
    return None if row is None else _row(row)


async def list(conn: aiosqlite.Connection, *, include_disabled: bool = True) -> list[UserRow]:
    """All users ordered by login_key (byte order), disabled ones included by default."""
    sql = f"SELECT {_COLUMNS} FROM users"
    if not include_disabled:
        sql += " WHERE disabled_at IS NULL"
    sql += " ORDER BY login_key"
    async with conn.execute(sql) as cur:
        return [_row(row) for row in await cur.fetchall()]


async def insert(
    conn: aiosqlite.Connection,
    login_key: str,
    *,
    email: str | None = None,
    display_name: str | None = None,
) -> UserRow:
    """Insert a user; a duplicate login_key raises sqlite3.IntegrityError."""
    cursor = await conn.execute(
        "INSERT INTO users (login_key, email, display_name) VALUES (?, ?, ?)",
        (login_key, email, display_name),
    )
    assert cursor.lastrowid is not None
    row = await get_by_id(conn, cursor.lastrowid)
    assert row is not None
    return row


async def update(
    conn: aiosqlite.Connection, user_id: int, changes: Mapping[str, str | None]
) -> UserRow | None:
    """Set exactly the given editable columns; None when the user does not exist."""
    unknown = changes.keys() - _EDITABLE
    if unknown:
        raise ValueError(f"not editable users columns: {', '.join(sorted(unknown))}")
    if changes:
        assignments = ", ".join(f"{name} = ?" for name in changes)
        await conn.execute(
            f"UPDATE users SET {assignments} WHERE id = ?", (*changes.values(), user_id)
        )
    return await get_by_id(conn, user_id)


async def set_disabled(conn: aiosqlite.Connection, user_id: int, disabled: bool) -> UserRow | None:
    """Set disabled_at once (later disables keep the first stamp), or clear it; None if missing.

    The UPDATE is value-idempotent and always issued, so callers inside
    ``metadata.transaction`` decide on the transaction's state, not a snapshot
    taken before it (gate2 G2-4).
    """
    if disabled:
        await conn.execute(
            "UPDATE users SET disabled_at = COALESCE(disabled_at, ?) WHERE id = ?",
            (now_iso(), user_id),
        )
    else:
        await conn.execute("UPDATE users SET disabled_at = NULL WHERE id = ?", (user_id,))
    return await get_by_id(conn, user_id)


async def unbind(conn: aiosqlite.Connection, user_id: int) -> UserRow | None:
    """Clear the bound OIDC subject so the next login binds the account again.

    Always issued: a caller inside ``metadata.transaction`` must clear whatever
    binding exists when its transaction runs, including one committed by a login
    while the caller was checking admin status (gate2 G2-4).
    """
    await conn.execute("UPDATE users SET oidc_sub = NULL WHERE id = ?", (user_id,))
    return await get_by_id(conn, user_id)
