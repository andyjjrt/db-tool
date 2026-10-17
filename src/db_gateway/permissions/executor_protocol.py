from collections.abc import Sequence
from typing import Protocol

from db_gateway.permissions.types import PgOp


class Executor(Protocol):
    async def apply(self, connection: str, ops: Sequence[PgOp]) -> None:
        """Run ops against one target DB in a single transaction, in order.

        Serialised per connection. Each op runs under SET ROLE <op.run_as(owner_role)>
        when that is not None, otherwise as dbg_admin; "no privileges were granted /
        revoked" warnings are errors.
        """
        ...
