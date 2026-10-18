"""Unit tests for the Reconciler's pure diff (plan §2.1, §10)."""

import asyncio
from collections.abc import Collection, Mapping
from dataclasses import replace

import pytest

from db_gateway.permissions import ids
from db_gateway.permissions.actual import ActualState, RowPolicy
from db_gateway.permissions.context import ConnectionLocks
from db_gateway.permissions.reconciler import (
    ReconcileFailed,
    Reconciler,
    ReconcileReport,
    diff,
    expected_ops,
    policy_ok,
)
from db_gateway.permissions.store import Tuple
from db_gateway.permissions.types import (
    CreateGroupRole,
    DeleteRowGrant,
    EnableRowPolicy,
    GrantAllTablesSelect,
    GrantDefaultSelect,
    GrantMembership,
    GrantTableSelect,
    MappingContext,
    PgOp,
    RevokeDefaultSelect,
    RevokeMembership,
    RevokeTableSelect,
    UpsertRowGrant,
)

ADMIN = "gw_admin"
CTX = MappingContext(connections=("prod", "dev"), default_privilege_owners={"prod": ("owner",)})

PASSTHROUGH = RowPolicy(
    "s",
    "t",
    "gw_passthrough",
    "*",
    True,
    ("PUBLIC",),
    "(NOT ( SELECT gateway_acl.is_managed()))",
    None,
)
READ = RowPolicy(
    "s",
    "t",
    "gw_read",
    "r",
    True,
    ("PUBLIC",),
    "(( SELECT gateway_acl.allow_all('s'::name, 't'::name) AS allow_all) OR (team = "
    "ANY (( SELECT gateway_acl.allowed_values('s'::name, 't'::name) AS allowed_values)"
    "::text[])))",
    None,
)


def state(**overrides: Collection[object]) -> ActualState:
    fields: dict[str, frozenset[object]] = {
        name: frozenset()
        for name in (
            "table_select",
            "schema_usage",
            "default_select",
            "memberships",
            "roles",
            "row_security",
            "policies",
            "row_grants",
            "column_types",
        )
    }
    fields.update({name: frozenset(value) for name, value in overrides.items()})
    return ActualState(**fields)  # type: ignore[arg-type]


RELATIONS: Mapping[str, Collection[str]] = {"s": {"t", "u", "v"}}


def run(
    tuples: Collection[Tuple] = (),
    actual: ActualState | None = None,
    groups: Collection[str] = (),
    relations: Mapping[str, Collection[str]] = RELATIONS,
    schemas: Collection[str] = ("s",),
):
    ops, invalid = expected_ops(tuples, CTX, "prod")
    plan = diff(
        ops=ops,
        groups=groups,
        actual=actual or state(),
        relations=relations,
        schemas=schemas,
        admin=ADMIN,
    )
    return plan.fixes, [*invalid, *plan.reported]


def kinds(reported: list) -> set[str]:
    return {d.kind for d in reported}


SCHEMA_RULE = Tuple(ids.group_member("a"), "reader", ids.db_schema("prod", "s"))
TABLE_RULE = Tuple(ids.group_member("a"), "reader", ids.db_table("prod", "s", "t"))
ROW_RULE = Tuple(ids.group_member("a"), "reader", ids.row_set("prod", "s", "t", "team", "x"))
DECLARE = Tuple(ids.column("team"), "row_column", ids.db_table("prod", "s", "t"))
MEMBER = Tuple(ids.user(7), "member", ids.group("a"))

SCHEMA_STATE = dict(
    roles={"g_a"},
    table_select={("s", n, "g_a") for n in "tuv"},
    default_select={("owner", "s", "g_a")},
    row_grants={("g_a", "s", "*", "*", "*")},
    schema_usage={("s", "gw_managed")},
)


def test_converged_state_has_no_fixes_and_no_reports() -> None:
    declared_state = dict(
        SCHEMA_STATE,
        roles={"g_a", "u_7"},
        table_select=SCHEMA_STATE["table_select"] | {("s", "t", "gw_managed")},
        row_grants={("g_a", "s", "*", "*", "*"), ("g_a", "s", "t", "team", "x")},
        row_security={("s", "t", True, True), ("s", "u", False, False)},
        policies={PASSTHROUGH, READ},
        column_types={("s", "t", "team", "text")},
        memberships={
            ("g_a", "u_7", ADMIN, False, True, True),
            ("gw_managed", "u_7", ADMIN, False, True, True),
        },
    )
    fixes, reported = run(
        [SCHEMA_RULE, ROW_RULE, DECLARE, MEMBER], state(**declared_state), groups=["a"]
    )
    assert (fixes, reported) == ([], [])


def test_missing_schema_rule_state_is_granted() -> None:
    fixes, _ = run([SCHEMA_RULE], state(roles={"g_a"}, schema_usage={("s", "gw_managed")}), ["a"])
    assert fixes == [
        GrantAllTablesSelect("s", "g_a"),
        GrantDefaultSelect("owner", "s", "g_a"),
        UpsertRowGrant("g_a", "s", "*", "*", "*"),
    ]


def test_missing_table_rule_state_is_granted() -> None:
    fixes, _ = run([TABLE_RULE], state(roles={"g_a"}), ["a"])
    assert fixes == [GrantTableSelect("s", "t", "g_a"), UpsertRowGrant("g_a", "s", "t", "*", "*")]


def test_one_missing_table_of_a_schema_reader_regrants_the_schema() -> None:
    present = dict(SCHEMA_STATE, table_select={("s", "t", "g_a"), ("s", "u", "g_a")})
    fixes, _ = run([SCHEMA_RULE], state(**present), ["a"])
    assert fixes == [GrantAllTablesSelect("s", "g_a")]


def test_unexpected_g_select_and_defaults_and_rows_are_revoked() -> None:
    actual = state(
        roles={"g_b"},
        table_select={("s", "t", "g_b")},
        default_select={("owner", "s", "g_b")},
        row_grants={("g_b", "s", "t", "team", "x")},
    )
    fixes, reported = run([], actual)
    assert set(fixes) == {
        RevokeTableSelect("s", "t", "g_b"),
        RevokeDefaultSelect("owner", "s", "g_b"),
        DeleteRowGrant("g_b", "s", "t", "x"),
    }
    assert kinds(reported) == {"unknown_group_role"}


def test_row_grant_with_wrong_column_is_replaced() -> None:
    actual = state(roles={"g_a"}, row_grants={("g_a", "s", "t", "other", "x")})
    fixes, _ = run([ROW_RULE], actual, ["a"])
    assert fixes == [
        DeleteRowGrant("g_a", "s", "t", "x"),
        UpsertRowGrant("g_a", "s", "t", "team", "x"),
    ]


def test_group_without_role_is_created_and_orphan_rows_are_deleted() -> None:
    actual = state(row_grants={("g_gone", "s", "*", "*", "*")})
    fixes, _ = run([], actual, ["a"])
    assert fixes == [CreateGroupRole("g_a"), DeleteRowGrant("g_gone", "s", "*", "*")]


def test_role_created_in_the_same_run_gets_its_rules() -> None:
    fixes, _ = run([TABLE_RULE], state(), ["a"])
    assert fixes == [
        CreateGroupRole("g_a"),
        GrantTableSelect("s", "t", "g_a"),
        UpsertRowGrant("g_a", "s", "t", "*", "*"),
    ]


def test_ops_the_executor_would_skip_are_not_planned() -> None:
    # no group in SQLite -> no role -> nothing for g_a; u_7 has no role yet
    fixes, _ = run([TABLE_RULE, MEMBER, ROW_RULE], state(), [])
    assert fixes == []
    fixes, _ = run([MEMBER], state(roles={"g_a"}), ["a"])
    assert fixes == []
    # table or schema missing
    fixes, _ = run([TABLE_RULE, SCHEMA_RULE], state(roles={"g_a"}), ["a"], relations={})
    assert fixes == [
        GrantDefaultSelect("owner", "s", "g_a"),
        UpsertRowGrant("g_a", "s", "*", "*", "*"),
        UpsertRowGrant("g_a", "s", "t", "*", "*"),
    ]


def test_membership_is_granted_and_unexpected_one_revoked() -> None:
    present = state(roles={"g_a", "u_7", "u_8"}, memberships={("g_a", "u_8", ADMIN, 0, 1, 1)})
    fixes, _ = run([MEMBER], present, ["a"])
    assert fixes == [RevokeMembership("g_a", "u_8"), GrantMembership("g_a", "u_7")]


def test_membership_grantor_drift_and_unmanaged_user_are_reported() -> None:
    actual = state(
        roles={"g_a", "u_7"}, memberships={("g_a", "u_7", "postgres", False, True, True)}
    )
    fixes, reported = run([MEMBER], actual, ["a"])
    assert fixes == []
    assert kinds(reported) == {"membership_grantor", "user_not_managed"}


def test_non_inheriting_required_membership_is_granted_again() -> None:
    present = {("g_a", "u_7", ADMIN, False, False, False)}
    fixes, _ = run([MEMBER], state(roles={"g_a", "u_7"}, memberships=present), ["a"])
    assert fixes == [GrantMembership("g_a", "u_7")]
    # an inheriting row from any grantor satisfies it
    present = {("g_a", "u_7", "postgres", False, True, True)}
    fixes, reported = run([MEMBER], state(roles={"g_a", "u_7"}, memberships=present), ["a"])
    assert fixes == []
    assert "membership_grantor" in kinds(reported)


def test_foreign_grantor_membership_is_never_revoked() -> None:
    both = {
        ("g_a", "u_7", "postgres", False, True, True),
        ("g_a", "u_7", ADMIN, False, True, True),
    }
    fixes, reported = run([], state(roles={"g_a", "u_7"}, memberships=both), ["a"])
    assert fixes == []
    assert "membership_grantor" in kinds(reported)
    admin_only = {("g_a", "u_7", ADMIN, False, True, True)}
    fixes, _ = run([], state(roles={"g_a", "u_7"}, memberships=admin_only), ["a"])
    assert fixes == [RevokeMembership("g_a", "u_7")]


def test_admin_named_like_a_personal_role_is_left_alone() -> None:
    actual = state(roles={"g_a", "u_7"}, memberships={("g_a", "u_7", "u_7", True, False, False)})
    ops, _ = expected_ops([MEMBER], CTX, "prod")
    plan = diff(
        ops=ops, groups=["a"], actual=actual, relations=RELATIONS, schemas=["s"], admin="u_7"
    )
    assert plan.fixes == []
    assert plan.reported == []
    plan = diff(
        ops=[], groups=["a"], actual=actual, relations=RELATIONS, schemas=["s"], admin="u_7"
    )
    assert plan.fixes == []


def test_policy_ok_requires_the_complete_expression() -> None:
    op = EnableRowPolicy("s", "t", "team")
    assert policy_ok(PASSTHROUGH, "gw_passthrough", op, column_type="text")
    assert policy_ok(READ, "gw_read", op, column_type="text")
    for using in (
        (READ.using or "")[:-1] + " OR true)",
        (READ.using or "").replace("(team =", "(team <> 'x' OR team ="),
    ):
        assert not policy_ok(replace(READ, using=using), "gw_read", op, column_type="text")
    altered = "NOT (SELECT gateway_acl.is_managed() UNION SELECT false ORDER BY 1 LIMIT 1)"
    assert not policy_ok(
        replace(PASSTHROUGH, using=f"({altered})"), "gw_passthrough", op, column_type="text"
    )
    assert not policy_ok(
        replace(PASSTHROUGH, command="r"), "gw_passthrough", op, column_type="text"
    )
    assert not policy_ok(replace(READ, permissive=False), "gw_read", op, column_type="text")
    assert not policy_ok(replace(READ, with_check="true"), "gw_read", op, column_type="text")
    assert not policy_ok(replace(READ, roles=("someone",)), "gw_read", op, column_type="text")
    shadowed = (READ.using or "").replace("(team =", "(team OPERATOR(public.=)")
    assert not policy_ok(replace(READ, using=shadowed), "gw_read", op, column_type="text")


def test_row_policy_is_enabled_when_any_part_is_wrong() -> None:
    good = dict(
        roles=set(),
        row_security={("s", "t", True, True)},
        policies={PASSTHROUGH, READ},
        table_select={("s", "t", "gw_managed")},
        column_types={("s", "t", "team", "text")},
    )
    assert run([DECLARE], state(**good))[0] == []
    broken: dict[str, dict[str, object]] = {
        "rls off": {"row_security": {("s", "t", False, False)}},
        "not forced": {"row_security": {("s", "t", True, False)}},
        "no passthrough": {"policies": {READ}},
        "no read": {"policies": {PASSTHROUGH}},
        "no managed select": {"table_select": set()},
        "column type unknown": {"column_types": set()},
        "uncast operand on a varchar column": {"column_types": {("s", "t", "team", "varchar")}},
    }
    wrong_column = RowPolicy(
        "s",
        "t",
        "gw_read",
        "r",
        True,
        ("PUBLIC",),
        (READ.using or "").replace("(team =", "(other ="),
        None,
    )
    broken["wrong column"] = {"policies": {PASSTHROUGH, wrong_column}}
    for name, change in broken.items():
        fixes, _ = run([DECLARE], state(**{**good, **change}))
        assert fixes == [EnableRowPolicy("s", "t", "team")], name


def test_policy_ok_accepts_quoted_column_and_rejects_other_table() -> None:
    op = EnableRowPolicy("s", "t", "Team")
    quoted = RowPolicy(
        "s",
        "t",
        "gw_read",
        "r",
        True,
        ("PUBLIC",),
        READ.using.replace("(team =", '(("Team")::text ='),  # type: ignore[union-attr]
        None,
    )
    assert policy_ok(quoted, "gw_read", op, column_type="character varying")
    # A text column is never deparsed with a cast, so the cast form is wrong for it.
    assert not policy_ok(quoted, "gw_read", op, column_type="text")
    other_table = EnableRowPolicy("s", "x", "Team")
    assert not policy_ok(quoted, "gw_read", other_table, column_type="character varying")
    assert not policy_ok(None, "gw_read", op, column_type="text")


def test_extra_permissive_policy_on_declared_table_is_reported() -> None:
    extra = RowPolicy("s", "t", "open", "r", True, ("PUBLIC",), "true", None)
    restrictive = RowPolicy("s", "t", "narrow", "r", False, ("PUBLIC",), "false", None)
    actual = state(
        row_security={("s", "t", True, True)},
        policies={PASSTHROUGH, READ, extra, restrictive},
        table_select={("s", "t", "gw_managed")},
        column_types={("s", "t", "team", "text")},
    )
    fixes, reported = run([DECLARE], actual)
    assert fixes == []
    extra_policies = [d for d in reported if d.kind == "extra_policy"]
    assert len(extra_policies) == 1 and "'open'" in extra_policies[0].message


def test_declared_table_missing_is_reported_not_fixed() -> None:
    fixes, reported = run([DECLARE], state())
    assert fixes == []
    assert kinds(reported) == {"declared_table_missing", "managed_usage_missing"}


def test_undeclared_policies_are_only_reported() -> None:
    actual = state(
        row_security={("s", "t", True, True)},
        policies={PASSTHROUGH, READ},
        schema_usage={("s", "gw_managed")},
    )
    fixes, reported = run([], actual)
    assert fixes == []
    assert [d.kind for d in reported] == ["undeclared_policy"]


def test_missing_managed_usage_is_reported_only_for_schemas_with_rules() -> None:
    fixes, reported = run([SCHEMA_RULE], state(**{**SCHEMA_STATE, "schema_usage": set()}), ["a"])
    assert fixes == []
    assert [d.kind for d in reported] == ["managed_usage_missing"]
    assert run([], state())[1] == []


def test_things_outside_the_gateway_scope_are_left_alone() -> None:
    actual = state(
        roles={"alice"},
        table_select={("s", "t", "alice"), ("s", "t", "app")},
        default_select={("owner", "s", "app")},
        memberships={
            ("g_x", "alice", "postgres", False, True, True),
            ("staff", "bob", "x", 0, 1, 1),
        },
        schema_usage={("s", "app")},
    )
    fixes, reported = run([], actual)
    assert fixes == []
    assert reported == []


def test_every_unexpected_row_grant_is_deleted_whatever_its_role() -> None:
    rows = {
        ("u_7", "s", "t", "*", "*"),
        ("gw_managed", "s", "t", "*", "*"),
        ("app", "s", "t", "team", "x"),
        ("g_gone", "s", "t", "team", "y"),
    }
    fixes, _ = run([], state(roles={"u_7"}, row_grants=rows))
    assert set(fixes) == {DeleteRowGrant(r[0], r[1], r[2], r[4]) for r in rows}


def test_unexpected_grants_to_managed_roles_are_reported_not_revoked() -> None:
    actual = state(
        roles={"u_7"},
        table_select={("s", "t", "gw_managed"), ("s", "t", "u_7")},
        default_select={("owner", "s", "u_7")},
        memberships={("gw_managed", "u_7", ADMIN, False, True, True)},
    )
    fixes, reported = run([], actual)
    assert fixes == []
    assert kinds(reported) == {"unexpected_grant"}
    assert len(reported) == 3


def test_tuples_of_other_connections_and_unmappable_tuples() -> None:
    other = Tuple(ids.group_member("a"), "reader", ids.db_table("dev", "s", "t"))
    unknown = Tuple(ids.group_member("a"), "reader", ids.db_table("gone", "s", "t"))
    fixes, reported = run([other, unknown], state(roles={"g_a"}), ["a"])
    assert fixes == []
    assert [d.kind for d in reported] == ["invalid_tuple"]


def test_two_row_columns_on_one_table_are_reported() -> None:
    second = Tuple(ids.column("zone"), "row_column", ids.db_table("prod", "s", "t"))
    fixes, reported = run([DECLARE, second], state(row_security={("s", "t", False, False)}))
    assert fixes == [EnableRowPolicy("s", "t", "team")]
    assert "conflicting_row_column" in kinds(reported)


def test_fix_list_has_no_duplicates() -> None:
    fixes: list[PgOp] = run([SCHEMA_RULE, TABLE_RULE], state(roles={"g_a"}), ["a"])[0]
    assert len(fixes) == len(set(fixes))


async def test_run_periodic_runs_at_start_then_every_interval_until_stopped() -> None:
    reconciler = Reconciler(None, None, None, None, ConnectionLocks())  # type: ignore[arg-type]
    calls = 0

    async def reconcile_all(dry_run: bool = False) -> dict[str, ReconcileReport]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("one bad round does not stop the loop")
        return {}

    reconciler.reconcile_all = reconcile_all  # type: ignore[method-assign]
    task = asyncio.create_task(reconciler.run_periodic(0.01))
    await asyncio.sleep(0.15)
    reconciler.stop()
    await asyncio.wait_for(task, 1)
    assert calls >= 3


async def test_reconcile_strict_raises_on_error_or_failed_fixes() -> None:
    reconciler = Reconciler(None, None, None, None, ConnectionLocks())  # type: ignore[arg-type]
    reports = [
        ReconcileReport("c"),
        ReconcileReport("c", error="boom"),
        ReconcileReport("c", failed=[CreateGroupRole("g_a")]),
    ]

    async def reconcile(connection: str, *, dry_run: bool = False) -> ReconcileReport:
        return reports.pop(0)

    reconciler.reconcile = reconcile  # type: ignore[method-assign]
    assert (await reconciler.reconcile_strict("c")).error is None
    for _ in range(2):
        with pytest.raises(ReconcileFailed) as raised:
            await reconciler.reconcile_strict("c")
        assert raised.value.report.connection == "c"
