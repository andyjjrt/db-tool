from collections.abc import Callable, Sequence

import pytest

from db_gateway.permissions import ids
from db_gateway.permissions.mapping import grant_ops, revoke_ops
from db_gateway.permissions.store import Tuple
from db_gateway.permissions.types import (
    ALL,
    DeleteRowGrant,
    DisableRowPolicy,
    EnableRowPolicy,
    GrantAllTablesSelect,
    GrantDefaultSelect,
    GrantMembership,
    GrantTableSelect,
    MappingContext,
    RevokeAllTablesSelect,
    RevokeDefaultSelect,
    RevokeMembership,
    RevokeTableSelect,
    TargetedOp,
    UpsertRowGrant,
    group_role,
    user_role,
)


def _ctx(
    connections: Sequence[str] = ("c",),
    owners: dict[str, Sequence[str]] | None = None,
    row_set_tables: dict[str, str] | None = None,
) -> MappingContext:
    return MappingContext(
        connections=connections,
        default_privilege_owners=owners or {},
        row_set_tables=row_set_tables or {},
    )


def test_group_membership_maps_to_each_connection() -> None:
    tuple_ = Tuple(user="user:12", relation="member", object="group:analysts")
    ctx = _ctx(connections=("primary", "reporting"))

    assert grant_ops(tuple_, ctx) == [
        TargetedOp("primary", GrantMembership(group_role("analysts"), user_role(12))),
        TargetedOp("reporting", GrantMembership(group_role("analysts"), user_role(12))),
    ]
    assert revoke_ops(tuple_, ctx) == [
        TargetedOp("reporting", RevokeMembership(group_role("analysts"), user_role(12))),
        TargetedOp("primary", RevokeMembership(group_role("analysts"), user_role(12))),
    ]


def test_schema_reader_maps_defaults_for_every_owner() -> None:
    tuple_ = Tuple(
        user="group:analysts#member",
        relation="reader",
        object=ids.db_schema("c", 'a"b'),
    )
    ctx = _ctx(owners={"c": ("owner_a", "owner_b")})
    role = group_role("analysts")

    assert grant_ops(tuple_, ctx) == [
        TargetedOp("c", GrantAllTablesSelect('a"b', role)),
        TargetedOp("c", GrantDefaultSelect("owner_a", 'a"b', role)),
        TargetedOp("c", GrantDefaultSelect("owner_b", 'a"b', role)),
        TargetedOp("c", UpsertRowGrant(role, 'a"b', ALL, ALL, ALL)),
    ]
    assert revoke_ops(tuple_, ctx) == [
        TargetedOp("c", DeleteRowGrant(role, 'a"b', ALL, ALL)),
        TargetedOp("c", RevokeDefaultSelect("owner_b", 'a"b', role)),
        TargetedOp("c", RevokeDefaultSelect("owner_a", 'a"b', role)),
        TargetedOp("c", RevokeAllTablesSelect('a"b', role)),
    ]


def test_table_reader_maps_table_select_and_row_grant() -> None:
    tuple_ = Tuple(
        user="group:analysts#member",
        relation="reader",
        object=ids.db_table("c", "sales", "events"),
    )
    role = group_role("analysts")

    assert grant_ops(tuple_, _ctx()) == [
        TargetedOp("c", GrantTableSelect("sales", "events", role)),
        TargetedOp("c", UpsertRowGrant(role, "sales", "events", ALL, ALL)),
    ]
    assert revoke_ops(tuple_, _ctx()) == [
        TargetedOp("c", DeleteRowGrant(role, "sales", "events", ALL)),
        TargetedOp("c", RevokeTableSelect("sales", "events", role)),
    ]


@pytest.mark.parametrize("column", ["team", 'team /:#@%="'])
def test_row_column_maps_enable_and_disable_row_policy(column: str) -> None:
    tuple_ = Tuple(
        user=ids.column(column),
        relation="row_column",
        object=ids.db_table("c", "sales", "events"),
    )

    assert grant_ops(tuple_, _ctx()) == [
        TargetedOp("c", EnableRowPolicy("sales", "events", column))
    ]
    assert revoke_ops(tuple_, _ctx()) == [TargetedOp("c", DisableRowPolicy("sales", "events"))]


def test_row_set_reader_maps_exact_column_value() -> None:
    tuple_ = Tuple(
        user="group:analysts#member",
        relation="reader",
        object=ids.row_set("c", "sales", "events", "team", "x'); drop table y;--"),
    )
    role = group_role("analysts")

    assert grant_ops(tuple_, _ctx()) == [
        TargetedOp(
            "c",
            UpsertRowGrant(role, "sales", "events", "team", "x'); drop table y;--"),
        )
    ]
    assert revoke_ops(tuple_, _ctx()) == [
        TargetedOp(
            "c",
            DeleteRowGrant(role, "sales", "events", "x'); drop table y;--"),
        )
    ]


def test_row_set_table_and_gateway_admin_tuples_are_no_ops() -> None:
    table_tuple = Tuple(
        user=ids.db_table("c", "sales", "events"),
        relation="table",
        object=ids.row_set("c", "sales", "events", "team", "a"),
    )
    admin_tuple = Tuple(user="user:12", relation="admin", object=ids.GATEWAY_MAIN)

    for tuple_ in (table_tuple, admin_tuple):
        assert grant_ops(tuple_, _ctx()) == []
        assert revoke_ops(tuple_, _ctx()) == []


def test_revoke_ops_match_hand_written_expected_ops() -> None:
    role = group_role("analysts")
    row_set_id = ids.row_set("c", "sales", "events", "team", "a")
    cases = [
        (
            Tuple("user:12", "member", "group:analysts"),
            _ctx(connections=("primary", "reporting")),
            [
                TargetedOp("reporting", RevokeMembership(role, user_role(12))),
                TargetedOp("primary", RevokeMembership(role, user_role(12))),
            ],
        ),
        (
            Tuple("group:analysts#member", "reader", "db_schema:c/s"),
            _ctx(owners={"c": ("owner_a", "owner_b")}),
            [
                TargetedOp("c", DeleteRowGrant(role, "s", ALL, ALL)),
                TargetedOp("c", RevokeDefaultSelect("owner_b", "s", role)),
                TargetedOp("c", RevokeDefaultSelect("owner_a", "s", role)),
                TargetedOp("c", RevokeAllTablesSelect("s", role)),
            ],
        ),
        (
            Tuple("group:analysts#member", "reader", "db_table:c/s/t"),
            _ctx(),
            [
                TargetedOp("c", DeleteRowGrant(role, "s", "t", ALL)),
                TargetedOp("c", RevokeTableSelect("s", "t", role)),
            ],
        ),
        (
            Tuple("column:team", "row_column", "db_table:c/s/t"),
            _ctx(),
            [TargetedOp("c", DisableRowPolicy("s", "t"))],
        ),
        (
            Tuple("group:analysts#member", "reader", row_set_id),
            _ctx(),
            [TargetedOp("c", DeleteRowGrant(role, "sales", "events", "a"))],
        ),
        (
            Tuple(
                "db_table:c/s/t",
                "table",
                "row_set:c/s/t/team=a",
            ),
            _ctx(),
            [],
        ),
        (Tuple("user:12", "admin", "gateway:main"), _ctx(), []),
    ]

    for tuple_, ctx, expected_revoke in cases:
        assert revoke_ops(tuple_, ctx) == expected_revoke


@pytest.mark.parametrize(
    "tuple_",
    [
        Tuple("group:g#member", "reader", "db_table:c/s/%2A"),
        Tuple("group:g#member", "reader", "row_set:c/s/%2A/col=v"),
        Tuple("group:g#member", "reader", "row_set:c/s/t/%2A=v"),
        Tuple("group:g#member", "reader", "row_set:c/s/t/col=%2A"),
        Tuple("db_table:c/s/%2A", "table", "row_set:c/s/t/col=v"),
        Tuple("db_table:c/s/t", "table", "row_set:c/s/t/%2A=v"),
    ],
)
def test_rejects_wildcards_inside_table_column_or_value(tuple_: Tuple) -> None:
    with pytest.raises(ValueError):
        grant_ops(tuple_, _ctx())


def test_rejects_row_set_parent_table_mismatch() -> None:
    row_set_id = ids.row_set("c", "sales", "events", "team", "a")
    tuple_ = Tuple("group:g#member", "reader", row_set_id)

    with pytest.raises(ValueError, match="does not match"):
        grant_ops(
            tuple_,
            _ctx(row_set_tables={row_set_id: ids.db_table("c", "sales", "orders")}),
        )


def test_rejects_unknown_types_relations_and_connections() -> None:
    with pytest.raises(ValueError):
        grant_ops(Tuple("group:g#member", "reader", "unknown:item"), _ctx())
    with pytest.raises(ValueError):
        grant_ops(Tuple("group:g#member", "admin", "db_schema:c/s"), _ctx())
    with pytest.raises(ValueError, match="connection"):
        grant_ops(Tuple("group:g#member", "reader", "db_table:other/s/t"), _ctx())


@pytest.mark.parametrize("mapping", [grant_ops, revoke_ops])
@pytest.mark.parametrize(
    "tuple_",
    [
        Tuple("column:team", "row_column", "db_table:other/s/t"),
        Tuple("column:team", "row_column", "db_table:c/s/%2A"),
        Tuple("column:%2A", "row_column", "db_table:c/s/t"),
        Tuple("group:g#member", "row_column", "db_table:c/s/t"),
        Tuple("user:12", "row_column", "db_table:c/s/t"),
        Tuple("db_table:c/s/t", "row_column", "db_table:c/s/t"),
        Tuple("team", "row_column", "db_table:c/s/t"),
        Tuple("column:", "row_column", "db_table:c/s/t"),
        Tuple("column:team/name", "row_column", "db_table:c/s/t"),
        Tuple("column:team#member", "row_column", "db_table:c/s/t"),
        Tuple("column:%74eam", "row_column", "db_table:c/s/t"),
    ],
)
def test_row_column_rejects_invalid_tuples(
    mapping: Callable[[Tuple, MappingContext], list[TargetedOp]], tuple_: Tuple
) -> None:
    with pytest.raises(ValueError):
        mapping(tuple_, _ctx())
