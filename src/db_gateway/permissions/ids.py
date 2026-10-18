"""OpenFGA object ids for gateway resources.

Each path segment is percent-encoded so that '/', '=', ':', '#', '@', '%' and
whitespace inside names or values never break the id structure. Parsing is
strict: an id is accepted only if re-encoding its parts gives the same id, so
every resource has exactly one id.
"""

from dataclasses import dataclass
from urllib.parse import quote, unquote

from db_gateway.permissions.store import Tuple

# OpenFGA rejects object ids longer than this (type prefix included).
MAX_OBJECT_LEN = 256

GATEWAY_MAIN = "gateway:main"

_SAFE = "-._~"  # unreserved; everything else in a segment gets %XX


class InvalidInput(ValueError):
    """Invalid caller input, rather than an unexpected internal ValueError."""


def _enc(segment: str) -> str:
    if segment == "":
        raise InvalidInput("empty id segment")
    try:
        return quote(segment, safe=_SAFE)
    except UnicodeError:
        raise InvalidInput("invalid Unicode in id segment") from None


def _dec(segment: str) -> str:
    """Strict inverse of _enc: only the canonical encoding of a segment is accepted."""
    try:
        value = unquote(segment, errors="strict")
    except UnicodeError:
        raise InvalidInput(f"invalid encoded id segment: {segment!r}") from None
    if _enc(value) != segment:
        raise InvalidInput(f"non-canonical id segment: {segment!r}")
    return value


def _check(obj: str) -> str:
    if len(obj) > MAX_OBJECT_LEN:
        raise InvalidInput(f"object id longer than {MAX_OBJECT_LEN}: {obj[:40]}...")
    return obj


def user(user_id: int) -> str:
    return f"user:{user_id}"


def group(name: str) -> str:
    return _check(f"group:{_enc(name)}")


def group_member(name: str) -> str:
    """The userset form used as the user side of rule tuples."""
    return f"{group(name)}#member"


def group_tuple(name: str) -> Tuple:
    """The gateway relation that determines whether a group exists."""
    return Tuple(group(name), "group", GATEWAY_MAIN)


def column(name: str) -> str:
    """The user side of db_table#row_column: the table's declared partition column."""
    return _check(f"column:{_enc(name)}")


def db_schema(connection: str, schema: str) -> str:
    return _check(f"db_schema:{_enc(connection)}/{_enc(schema)}")


def db_table(connection: str, schema: str, table: str) -> str:
    return _check(f"db_table:{_enc(connection)}/{_enc(schema)}/{_enc(table)}")


def row_set(connection: str, schema: str, table: str, column: str, value: str) -> str:
    return _check(
        f"row_set:{_enc(connection)}/{_enc(schema)}/{_enc(table)}/{_enc(column)}={_enc(value)}"
    )


@dataclass(frozen=True, slots=True)
class SchemaRef:
    connection: str
    schema: str


@dataclass(frozen=True, slots=True)
class TableRef:
    connection: str
    schema: str
    table: str


@dataclass(frozen=True, slots=True)
class RowSetRef:
    connection: str
    schema: str
    table: str
    column: str
    value: str


def _split(obj: str, type_: str) -> str:
    prefix = f"{type_}:"
    if not obj.startswith(prefix):
        raise InvalidInput(f"not a {type_} id: {obj}")
    return obj[len(prefix) :]


def parse_user(obj: str) -> int:
    body = _split(obj, "user")
    if not body.isascii() or not body.isdigit() or str(int(body)) != body:
        raise InvalidInput(f"malformed user id: {obj}")
    return int(body)


def parse_group(obj: str) -> str:
    """Accepts "group:<name>" or the userset "group:<name>#member"."""
    body = _split(obj, "group")
    if body.endswith("#member"):
        body = body[: -len("#member")]
    if "#" in body:
        raise InvalidInput(f"unexpected relation in group id: {obj}")
    return _dec(body)


def parse_column(obj: str) -> str:
    body = _split(obj, "column")
    if "/" in body or "#" in body:
        raise InvalidInput(f"malformed column id: {obj}")
    return _dec(body)


def parse_db_schema(obj: str) -> SchemaRef:
    parts = _split(obj, "db_schema").split("/")
    if len(parts) != 2:
        raise InvalidInput(f"malformed db_schema id: {obj}")
    return SchemaRef(*map(_dec, parts))


def parse_db_table(obj: str) -> TableRef:
    parts = _split(obj, "db_table").split("/")
    if len(parts) != 3:
        raise InvalidInput(f"malformed db_table id: {obj}")
    return TableRef(*map(_dec, parts))


def parse_row_set(obj: str) -> RowSetRef:
    parts = _split(obj, "row_set").split("/")
    if len(parts) != 4 or parts[3].count("=") != 1:
        raise InvalidInput(f"malformed row_set id: {obj}")
    column, value = parts[3].split("=")
    return RowSetRef(*map(_dec, [*parts[:3], column, value]))
