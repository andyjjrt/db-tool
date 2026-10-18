import pytest

from db_gateway.permissions import ids

TRICKY = ["a/b", "x=y", "c:d", "e#f", "g@h", "100%", "with space", "tab\tnl\n", "中文", "-._~"]


@pytest.mark.parametrize("value", TRICKY)
def test_row_set_round_trip(value: str) -> None:
    obj = ids.row_set(value, value, value, value, value)
    ref = ids.parse_row_set(obj)
    assert ref == ids.RowSetRef(value, value, value, value, value)
    body = obj.removeprefix("row_set:")
    assert body.count("/") == 3 and body.count("=") == 1
    assert not any(ch in body for ch in ":#@ \t\n")


@pytest.mark.parametrize("value", TRICKY)
def test_table_schema_group_round_trip(value: str) -> None:
    table = ids.db_table(value, value, value)
    assert ids.parse_db_table(table) == ids.TableRef(value, value, value)
    assert ids.parse_db_schema(ids.db_schema(value, value)) == ids.SchemaRef(value, value)
    assert ids.parse_group(ids.group(value)) == value
    assert ids.parse_group(ids.group_member(value)) == value
    assert ids.parse_column(ids.column(value)) == value
    assert ids.column(value).count("/") == 0


def test_column() -> None:
    assert ids.column("team") == "column:team"
    with pytest.raises(ValueError):
        ids.parse_column("db_table:prod/s/t")
    with pytest.raises(ValueError):
        ids.parse_column("column:a b")


def test_user() -> None:
    assert ids.user(12) == "user:12"
    assert ids.parse_user("user:12") == 12


def test_plain_names_stay_readable() -> None:
    assert ids.row_set("prod", "s", "t", "team", "a") == "row_set:prod/s/t/team=a"
    assert ids.group_member("analysts") == "group:analysts#member"


def test_rejects_wrong_type_and_shape() -> None:
    with pytest.raises(ValueError):
        ids.parse_db_table("db_schema:prod/s")
    with pytest.raises(ValueError):
        ids.parse_db_table("db_table:prod/s")
    with pytest.raises(ValueError):
        ids.parse_row_set("row_set:prod/s/t/team")
    with pytest.raises(ValueError):
        ids.db_table("prod", "", "t")


def test_length_limit() -> None:
    with pytest.raises(ValueError):
        ids.row_set("prod", "s", "t", "team", "v" * 300)


@pytest.mark.parametrize(
    "obj",
    [
        "db_table:prod/s/%2f",  # lowercase hex: same bytes as %2F, not canonical
        "db_table:prod/s/%41",  # 'A' needlessly encoded
        "db_table:prod/s/%FF",  # invalid UTF-8
        "row_set:prod/s/t/team=a b",  # raw space
    ],
)
def test_rejects_non_canonical(obj: str) -> None:
    with pytest.raises(ValueError):
        if obj.startswith("row_set:"):
            ids.parse_row_set(obj)
        else:
            ids.parse_db_table(obj)


@pytest.mark.parametrize(
    "obj", ["user: 12", "user:012", "user:+12", "user:1_2", "user:-1", "user:"]
)
def test_parse_user_is_canonical(obj: str) -> None:
    with pytest.raises(ValueError):
        ids.parse_user(obj)
