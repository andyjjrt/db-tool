import json

import aiosqlite

_FIELDS = (
    "user_id",
    "activation_id",
    "session_id",
    "pg_role",
    "connection_id",
    "sql_text",
    "rows",
    "duration_ms",
    "error",
    "detail",
)


async def record(conn: aiosqlite.Connection, kind: str, **fields: object) -> None:
    """Insert an audit event; callers must write inside metadata.transaction()."""
    unknown = fields.keys() - set(_FIELDS)
    if unknown:
        raise ValueError(f"Unknown audit fields: {', '.join(sorted(unknown))}")
    if fields.get("detail") is not None and not isinstance(fields["detail"], str):
        fields["detail"] = json.dumps(fields["detail"])
    columns = ["kind", *(name for name in _FIELDS if name in fields)]
    values = [kind, *(fields[name] for name in columns[1:])]
    await conn.execute(
        f"INSERT INTO audit_log ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
        values,
    )
