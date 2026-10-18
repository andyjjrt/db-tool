"""Access to the permission source of truth (OpenFGA).

Business code depends only on this module; the OpenFGA SDK is confined to
store_openfga.py so the store can later move behind its own service.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol

# OpenFGA's default per-request limit (OPENFGA_MAX_TUPLES_PER_WRITE).
MAX_TUPLES_PER_WRITE = 100


@dataclass(frozen=True, slots=True)
class Tuple:
    """One relationship tuple, in OpenFGA's string form.

    user:     "user:12", "group:analysts#member", "db_table:prod/s/t", "column:team"
    relation: "member", "reader", "table", "admin", "row_column"
    object:   "group:analysts", "db_table:prod/s/t", "row_set:prod/s/t/team=a"
    """

    user: str
    relation: str
    object: str


class ChangeOp(Enum):
    WRITE = "write"
    DELETE = "delete"


@dataclass(frozen=True, slots=True)
class Change:
    tuple: Tuple
    op: ChangeOp
    timestamp: datetime


@dataclass(frozen=True, slots=True)
class ChangesPage:
    changes: Sequence[Change]
    # Pass back to read_changes to continue. Unchanged when there was nothing new.
    # "" means "no position yet" and is treated exactly like None.
    continuation_token: str


class PermissionStoreUnavailable(Exception):
    """The store cannot be reached; the admin API maps this to 503."""


class ContinuationTokenInvalid(Exception):
    """read_changes was given a token the store no longer accepts (expired or malformed).

    The Syncer falls back to a full reconcile and restarts from the current position.
    """


class PermissionStore(Protocol):
    async def write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
        """Apply writes and deletes atomically.

        Writing a tuple that already exists and deleting one that does not are
        no-ops, not errors (OpenFGA: on_duplicate="ignore" / on_missing="ignore").
        The same tuple in both writes and deletes is a ValueError.
        len(writes) + len(deletes) must not exceed MAX_TUPLES_PER_WRITE
        (ValueError); callers batch.
        """
        ...

    async def read(
        self, object: str | None = None, relation: str | None = None, user: str | None = None
    ) -> list[Tuple]:
        """Stored tuples matching the filter (no rewrite/expansion). Returns all pages.

        object:
          None                 every tuple in the store (relation and user must be None)
          "db_table:prod/s/t"  that object
          "row_set:"           every object of that type; user is then required
        Filter combinations outside these raise ValueError in every implementation.
        """
        ...

    async def read_changes(
        self, continuation_token: str | None, page_size: int = 100
    ) -> ChangesPage:
        """Changes after continuation_token (None or "" = from the beginning), oldest first.

        Raises ContinuationTokenInvalid if the store rejects the token.
        """
        ...

    async def check(self, user: str, relation: str, object: str) -> bool: ...
