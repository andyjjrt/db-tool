"""PostgreSQL operations produced by the tuple mapping and run by the executor.

Every op is idempotent: granting twice, revoking something absent, upserting
an existing row_grants row or deleting a missing one all succeed and change
nothing.

Replay safety (plan §2.1): the Syncer may replay old changes after the roles or
objects they name are gone, and one failing op would stop the connection's
token forever. So before running an op the executor checks what it names and
skips (logging the reason) instead of failing:
  - any op whose role (group role, member role, grantee) does not exist;
  - any object-privilege or default-privilege op whose schema or table does not
    exist;
  - UpsertRowGrant whose group role does not exist (it would leave an orphan
    row_grants row);
  - EnableRowPolicy / DisableRowPolicy whose table does not exist.
Never skipped: DeleteRowGrant and DropGroupRole. Deleting rows is idempotent,
and skipping them would leave rows that a group recreated under the same name
inherits (roles are cluster-global, so another connection may have dropped the
role first). A DROP ROLE blocked by privileges in another database on the same
cluster is a transient error: it is retried, not skipped.
Order: the skip check comes first; for ops that run, a "no privileges were
granted / revoked" WARNING is then an error (RevokeMembership has its own
grantor rule, below).
Everything else that errors is a real error.

Every op runs as the connection's admin account itself (no SET ROLE). That
account is the database owner or a superuser, set up by hand by the operator;
the gateway never migrates or escalates on the target DB. What it needs
(docs/target-db-setup.md; targetdb.check reports what is missing):
  - CREATEROLE and ADMIN OPTION on gw_managed (group roles, memberships);
  - ownership of, or inherited membership in the owner of, every table in the
    managed schemas (GRANT/REVOKE, ENABLE RLS, CREATE POLICY);
  - membership in every role of default_privilege_owners (ALTER DEFAULT
    PRIVILEGES FOR ROLE).
If it lacks a privilege the op fails and the error is reported; it is not
worked around.
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
    pass


# --- roles and membership ---


@dataclass(frozen=True, slots=True)
class CreateGroupRole(PgOp):
    role: str  # CREATE ROLE <role> NOLOGIN, if absent


@dataclass(frozen=True, slots=True)
class DropGroupRole(PgOp):
    """DELETE FROM gateway_acl.row_grants WHERE group_role = <role>, then DROP ROLE IF EXISTS.

    Both in the same transaction, so no row_grants row outlives its role and a
    group recreated under the same name starts with no row access. The role
    holds no objects, only grants.
    """

    role: str


@dataclass(frozen=True, slots=True)
class GrantMembership(PgOp):
    """GRANT <group> TO <member> WITH INHERIT TRUE.

    Granting again repairs a membership granted earlier with INHERIT FALSE.

    The executor skips it when either role does not exist (a personal role is
    created at the user's first session, which then applies its memberships).
    """

    group: str
    member: str


@dataclass(frozen=True, slots=True)
class RevokeMembership(PgOp):
    """REVOKE <group> FROM <member>.

    PG16+ only removes a membership granted by the current role; anything else
    is a WARNING and the member keeps access. So the executor reads
    pg_auth_members first: no membership or either role missing → skip; granted
    by the admin account → plain REVOKE; granted by another role → REVOKE ... GRANTED BY
    <grantor> (the admin account holds ADMIN on group roles it created), and an error if
    that is not possible.
    """

    group: str
    member: str


# --- object privileges ---
#
# GRANT/REVOKE on objects the current role does not own only raises a WARNING
# ("no privileges were granted"); the executor must treat that warning as an error.


@dataclass(frozen=True, slots=True)
class GrantSchemaUsage(PgOp):
    schema: str
    role: str


@dataclass(frozen=True, slots=True)
class GrantTableSelect(PgOp):
    schema: str
    table: str
    role: str


@dataclass(frozen=True, slots=True)
class RevokeTableSelect(PgOp):
    schema: str
    table: str
    role: str


@dataclass(frozen=True, slots=True)
class GrantAllTablesSelect(PgOp):
    schema: str  # GRANT SELECT ON ALL TABLES IN SCHEMA <schema> TO <role>
    role: str


@dataclass(frozen=True, slots=True)
class RevokeAllTablesSelect(PgOp):
    schema: str
    role: str


@dataclass(frozen=True, slots=True)
class GrantDefaultSelect(PgOp):
    """ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA <schema>
    GRANT SELECT ON TABLES TO <role>."""

    owner: str
    schema: str
    role: str


@dataclass(frozen=True, slots=True)
class RevokeDefaultSelect(PgOp):
    owner: str
    schema: str
    role: str


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
class EnableRowPolicy(PgOp):
    """ENABLE + FORCE RLS, CREATE POLICY gw_passthrough and gw_read, GRANT SELECT TO gw_managed."""

    schema: str
    table: str
    column: str


@dataclass(frozen=True, slots=True)
class DisableRowPolicy(PgOp):
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
