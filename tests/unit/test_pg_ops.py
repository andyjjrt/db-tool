from dataclasses import dataclass

import pytest
from psycopg import sql

from db_gateway.permissions import types
from db_gateway.permissions.pg_ops import (
    RequiredObjects,
    render,
    required_objects,
    required_roles,
)
from db_gateway.permissions.types import (
    CreateGroupRole,
    DeleteRowGrant,
    DisableRowPolicy,
    DropGroupRole,
    EnableRowPolicy,
    GrantAllTablesSelect,
    GrantDefaultSelect,
    GrantMembership,
    GrantSchemaUsage,
    GrantTableSelect,
    PgOp,
    RevokeAllTablesSelect,
    RevokeDefaultSelect,
    RevokeMembership,
    RevokeTableSelect,
    UpsertRowGrant,
)


def _sql(op: PgOp) -> list[str]:
    return [statement.as_string(None) for statement in render(op)]


def _subclasses(cls: type[PgOp]) -> set[type[PgOp]]:
    found: set[type[PgOp]] = set()
    for child in cls.__subclasses__():
        found.add(child)
        found.update(_subclasses(child))
    return found


def _sample_ops() -> dict[type[PgOp], PgOp]:
    ops: list[PgOp] = [
        CreateGroupRole('g"; select 1;--'),
        DropGroupRole("g"),
        GrantMembership("g", "u"),
        RevokeMembership("g", "u"),
        GrantSchemaUsage("s", "g"),
        GrantTableSelect("s", "t", "g"),
        RevokeTableSelect("s", "t", "g"),
        GrantAllTablesSelect("s", "g"),
        RevokeAllTablesSelect("s", "g"),
        GrantDefaultSelect("owner", "s", "g"),
        RevokeDefaultSelect("owner", "s", "g"),
        UpsertRowGrant("g", "s", "t", "c", "v"),
        DeleteRowGrant("g", "s", "t", "v"),
        EnableRowPolicy("s", "t", "c"),
        DisableRowPolicy("s", "t"),
    ]
    return {type(op): op for op in ops}


def test_every_concrete_pg_op_has_a_renderer() -> None:
    sample_ops = _sample_ops()
    concrete = {
        op_type for op_type in _subclasses(PgOp) if vars(types).get(op_type.__name__) is op_type
    }

    assert set(sample_ops) == concrete
    for op in sample_ops.values():
        assert _sql(op)


def test_required_objects_covers_every_concrete_pg_op() -> None:
    sample_ops = _sample_ops()
    concrete = {
        op_type for op_type in _subclasses(PgOp) if vars(types).get(op_type.__name__) is op_type
    }
    expected = {
        CreateGroupRole: RequiredObjects(),
        DropGroupRole: RequiredObjects(),
        GrantMembership: RequiredObjects(roles=("g", "u")),
        RevokeMembership: RequiredObjects(roles=("g", "u")),
        GrantSchemaUsage: RequiredObjects(roles=("g",), schemas=("s",)),
        GrantTableSelect: RequiredObjects(roles=("g",), schemas=("s",), tables=(("s", "t"),)),
        RevokeTableSelect: RequiredObjects(roles=("g",), schemas=("s",), tables=(("s", "t"),)),
        GrantAllTablesSelect: RequiredObjects(roles=("g",), schemas=("s",)),
        RevokeAllTablesSelect: RequiredObjects(roles=("g",), schemas=("s",)),
        GrantDefaultSelect: RequiredObjects(roles=("owner", "g"), schemas=("s",)),
        RevokeDefaultSelect: RequiredObjects(roles=("owner", "g"), schemas=("s",)),
        UpsertRowGrant: RequiredObjects(roles=("g",)),
        DeleteRowGrant: RequiredObjects(),
        EnableRowPolicy: RequiredObjects(
            roles=(types.GW_MANAGED,), schemas=("s",), tables=(("s", "t"),)
        ),
        DisableRowPolicy: RequiredObjects(
            roles=(types.GW_MANAGED,), schemas=("s",), tables=(("s", "t"),)
        ),
    }

    assert set(sample_ops) == concrete == set(expected)
    assert {op_type: required_objects(op) for op_type, op in sample_ops.items()} == expected


def test_create_group_role_is_idempotent_and_quotes_role_as_literal() -> None:
    statement = _sql(CreateGroupRole("g'); DROP ROLE admin;--"))[0]

    assert statement.startswith("DO $gw$")
    assert "IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles" in statement
    assert "format('CREATE ROLE %I NOLOGIN', 'g''); DROP ROLE admin;--')" in statement


def test_drop_role_and_membership_render_identifiers() -> None:
    assert _sql(DropGroupRole('g"one')) == [
        'DELETE FROM "gateway_acl"."row_grants" WHERE "group_role" = \'g"one\'',
        'DROP ROLE IF EXISTS "g""one"',
    ]
    assert _sql(GrantMembership('g"one', "u_1")) == ['GRANT "g""one" TO "u_1" WITH INHERIT TRUE']
    assert _sql(RevokeMembership("g", "u")) == ['REVOKE "g" FROM "u"']
    assert required_roles(GrantMembership("g", "u")) == ("g", "u")
    assert required_roles(RevokeMembership("g", "u")) == ("g", "u")


@pytest.mark.parametrize(
    ("op", "expected"),
    [
        (GrantSchemaUsage('s"1', "g"), 'GRANT USAGE ON SCHEMA "s""1" TO "g"'),
        (
            GrantTableSelect('s"1', "t", "g"),
            'GRANT SELECT ON TABLE "s""1"."t" TO "g"',
        ),
        (
            RevokeTableSelect("s", "t", "g"),
            'REVOKE SELECT ON TABLE "s"."t" FROM "g"',
        ),
        (
            GrantAllTablesSelect("s", "g"),
            'GRANT SELECT ON ALL TABLES IN SCHEMA "s" TO "g"',
        ),
        (
            RevokeAllTablesSelect("s", "g"),
            'REVOKE SELECT ON ALL TABLES IN SCHEMA "s" FROM "g"',
        ),
        (
            GrantDefaultSelect("owner", "s", "g"),
            'ALTER DEFAULT PRIVILEGES FOR ROLE "owner" IN SCHEMA "s" GRANT SELECT ON TABLES TO "g"',
        ),
        (
            RevokeDefaultSelect("owner", "s", "g"),
            'ALTER DEFAULT PRIVILEGES FOR ROLE "owner" IN SCHEMA "s" '
            'REVOKE SELECT ON TABLES FROM "g"',
        ),
    ],
)
def test_privilege_ops_render(op: PgOp, expected: str) -> None:
    assert _sql(op) == [expected]
    assert required_roles(op) == ()


def test_row_grant_dml_safely_quotes_identifiers_and_values() -> None:
    hostile = "x'); drop table y;--"
    upsert = _sql(UpsertRowGrant('g"1', 'a"b', "events", "team", hostile))[0]

    assert upsert == (
        'INSERT INTO "gateway_acl"."row_grants" '
        '("group_role", "schema_name", "table_name", "column_name", "value") '
        "VALUES ('g\"1', 'a\"b', 'events', 'team', 'x''); drop table y;--') "
        "ON CONFLICT DO NOTHING"
    )
    delete = _sql(DeleteRowGrant("g", "s", "t", hostile))[0]
    assert delete.startswith('DELETE FROM "gateway_acl"."row_grants" WHERE ')
    assert "\"group_role\" = 'g'" in delete
    assert "\"schema_name\" = 's'" in delete
    assert "\"table_name\" = 't'" in delete
    assert "\"value\" = 'x''); drop table y;--'" in delete


def test_enable_policy_matches_required_subquery_form() -> None:
    statements = _sql(EnableRowPolicy('a"b', "events", "team"))

    assert len(statements) == 7
    assert statements[0] == 'ALTER TABLE "a""b"."events" ENABLE ROW LEVEL SECURITY'
    assert statements[1] == 'ALTER TABLE "a""b"."events" FORCE ROW LEVEL SECURITY'
    assert statements[2] == 'DROP POLICY IF EXISTS "gw_passthrough" ON "a""b"."events"'
    assert statements[3] == (
        'CREATE POLICY "gw_passthrough" ON "a""b"."events" '
        'USING (NOT (SELECT "gateway_acl"."is_managed"()))'
    )
    assert statements[4] == 'DROP POLICY IF EXISTS "gw_read" ON "a""b"."events"'
    assert statements[5] == (
        'CREATE POLICY "gw_read" ON "a""b"."events" FOR SELECT USING '
        '((SELECT "gateway_acl"."allow_all"(\'a"b\', \'events\')) OR "team"::text '
        '= ANY ((SELECT "gateway_acl"."allowed_values"(\'a"b\', \'events\'))::text[]))'
    )
    assert "TO gw_managed" not in statements[5]
    assert statements[6] == 'GRANT SELECT ON TABLE "a""b"."events" TO "gw_managed"'


def test_disable_policy_drops_policies_before_rls_and_select() -> None:
    assert _sql(DisableRowPolicy("s", "t")) == [
        'DROP POLICY IF EXISTS "gw_passthrough" ON "s"."t"',
        'DROP POLICY IF EXISTS "gw_read" ON "s"."t"',
        'ALTER TABLE "s"."t" NO FORCE ROW LEVEL SECURITY',
        'ALTER TABLE "s"."t" DISABLE ROW LEVEL SECURITY',
        'REVOKE SELECT ON TABLE "s"."t" FROM "gw_managed"',
    ]


def test_unknown_pg_operation_raises_type_error() -> None:
    @dataclass(frozen=True)
    class UnknownOp(PgOp):
        pass

    with pytest.raises(TypeError, match="UnknownOp"):
        render(UnknownOp())


def test_policy_schema_and_values_are_psycopg_composables() -> None:
    assert isinstance(sql.Identifier('a"b'), sql.Composable)
    assert isinstance(sql.Literal("x'); drop table y;--"), sql.Composable)
