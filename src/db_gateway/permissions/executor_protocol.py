from collections.abc import Sequence
from typing import Protocol

from db_gateway.permissions.types import PgOp


class Executor(Protocol):
    async def apply(self, connection: str, ops: Sequence[PgOp]) -> None:
        """Run ops against one target DB in a single transaction, in order.

        Serialised per connection. Ops run as the connection's admin account (no
        SET ROLE); "no privileges were granted / revoked" warnings are errors.
        Ops whose roles or objects are missing are skipped (see types.py).
        """
        ...
