"""PostgreSQL operations produced by the tuple mapping and run by the executor.

Every op is idempotent: granting twice, revoking something absent, upserting
an existing row_grants row or deleting a missing one all succeed and change
nothing.

Which role runs an op is given by run_as(owner_role): None means dbg_admin
itself; otherwise the executor runs the op under SET ROLE <that role>.
Object-privilege and RLS ops run as the connection's owner role; default
privileges run as the role whose defaults they change.

Role requirements per connection (checked when a connection is registered;
a connection that fails them is refused):
  - owner_role owns, or inherits the privileges of the owner of, every table in
    the managed schemas: for every X in default_privilege_owners,
    pg_has_role(owner_role, X, 'USAGE').
  - dbg_admin can SET ROLE to owner_role and to every X in
    default_privilege_owners: pg_has_role(dbg_admin, X, 'SET').
  - dbg_admin has CREATEROLE (group roles) and ADMIN OPTION on gw_managed.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

GW_MANAGED = "gw_managed"

# row_grants wildcard: all rows (value) or the whole schema (table_name, column_name).
# Never a legal partition value, column name or table name: RuleService rejects it on write and
# the mapping raises ValueError if it meets one inside an id.
ALL = "*"


def group_role(group_name: str) -> str:
    return f"g_{group_name}"


def user_role(user_id: int) -> str:
    return f"u_{user_id}"


@dataclass(frozen=True, slots=True)
class PgOp:
    def run_as(self, owner_role: str) -> str | None:
        return None


@dataclass(frozen=True, slots=True)
class _AsOwner(PgOp):
    def run_as(self, owner_role: str) -> str | None:
        return owner_role


# --- roles and membership (dbg_admin) ---


@dataclass(frozen=True, slots=True)
class CreateGroupRole(PgOp):
    role: str  # CREATE ROLE <role> NOLOGIN, if absent


@dataclass(frozen=True, slots=True)
class DropGroupRole(PgOp):
    role: str  # DROP ROLE IF EXISTS <role>; the role holds no objects, only grants


@dataclass(frozen=True, slots=True)
class GrantMembership(PgOp):
    """GRANT <group> TO <member>.

    The executor skips it when <member> does not exist yet (a personal role is
    created at the user's first session, which then applies its memberships).
    """

    group: str
    member: str


@dataclass(frozen=True, slots=True)
class RevokeMembership(PgOp):
    group: str  # skipped when either role does not exist
    member: str


# --- object privileges (owner role) ---
#
# GRANT/REVOKE on objects the current role does not own only raises a WARNING
# ("no privileges were granted"); the executor must treat that warning as an error.


@dataclass(frozen=True, slots=True)
class GrantSchemaUsage(_AsOwner):
    schema: str
    role: str


@dataclass(frozen=True, slots=True)
class GrantTableSelect(_AsOwner):
    schema: str
    table: str
    role: str


@dataclass(frozen=True, slots=True)
class RevokeTableSelect(_AsOwner):
    schema: str
    table: str
    role: str


@dataclass(frozen=True, slots=True)
class GrantAllTablesSelect(_AsOwner):
    schema: str  # GRANT SELECT ON ALL TABLES IN SCHEMA <schema> TO <role>
    role: str


@dataclass(frozen=True, slots=True)
class RevokeAllTablesSelect(_AsOwner):
    schema: str
    role: str


@dataclass(frozen=True, slots=True)
class GrantDefaultSelect(PgOp):
    """ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA <schema>
    GRANT SELECT ON TABLES TO <role>. Runs as <owner>."""

    owner: str
    schema: str
    role: str

    def run_as(self, owner_role: str) -> str | None:
        return self.owner


@dataclass(frozen=True, slots=True)
class RevokeDefaultSelect(PgOp):
    owner: str
    schema: str
    role: str

    def run_as(self, owner_role: str) -> str | None:
        return self.owner


# --- row-level security ---


@dataclass(frozen=True, slots=True)
class UpsertRowGrant(PgOp):
    """INSERT INTO gateway_acl.row_grants ... ON CONFLICT DO NOTHING."""

    group_role: str
    schema: str
    table: str  # ALL for a db_schema reader
    column: str  # ALL for a db_schema or db_table reader
    value: str  # ALL for every row


@dataclass(frozen=True, slots=True)
class DeleteRowGrant(PgOp):
    group_role: str
    schema: str
    table: str
    value: str


@dataclass(frozen=True, slots=True)
class EnableRowPolicy(_AsOwner):
    """ENABLE + FORCE RLS, CREATE POLICY gw_passthrough and gw_read, GRANT SELECT TO gw_managed."""

    schema: str
    table: str
    column: str


@dataclass(frozen=True, slots=True)
class DisableRowPolicy(_AsOwner):
    """DROP both policies, NO FORCE + DISABLE RLS, REVOKE SELECT FROM gw_managed."""

    schema: str
    table: str


# --- mapping input/output ---


@dataclass(frozen=True, slots=True)
class MappingContext:
    """What the pure mapping needs besides the tuple itself.

    A row_set's connection/schema/table/column/value are taken from its id
    (ids.parse_row_set): the parent `table` tuple may already be gone when a
    delete is replayed. row_set_tables, when it has an entry, is only a
    consistency check against the `table` relation.
    """

    connections: Sequence[str]  # every connection name; membership applies to all
    default_privilege_owners: Mapping[str, Sequence[str]]  # connection -> owner roles
    row_set_tables: Mapping[str, str] = field(default_factory=dict)  # row_set id -> db_table id


@dataclass(frozen=True, slots=True)
class TargetedOp:
    connection: str
    op: PgOp
