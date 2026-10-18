from __future__ import annotations

import pytest

from db_gateway.permissions.store import (
    MAX_TUPLES_PER_WRITE,
    ChangeOp,
    ContinuationTokenInvalid,
    PermissionStore,
    Tuple,
)
from db_gateway.permissions.store_memory import MemoryStore


class StoreContract:
    @pytest.fixture
    def store(self) -> PermissionStore:
        raise NotImplementedError

    async def test_write_and_delete_are_idempotent(self, store: PermissionStore) -> None:
        item = Tuple(
            user="user:1",
            relation="member",
            object="group:analysts",
        )
        await store.write(writes=[item])
        await store.write(writes=[item])
        assert await store.read(object=item.object) == [item]

        await store.write(deletes=[item])
        await store.write(deletes=[item])
        assert await store.read(object=item.object) == []

    async def test_row_column_tuple_round_trips_and_filters(self, store: PermissionStore) -> None:
        row_column = Tuple(
            user="column:team",
            relation="row_column",
            object="db_table:prod/sales/orders",
        )
        reader = Tuple(
            user="group:analysts#member",
            relation="reader",
            object=row_column.object,
        )
        await store.write(writes=[row_column, reader])

        assert set(await store.read()) == {row_column, reader}
        assert set(await store.read(object=row_column.object)) == {row_column, reader}
        assert await store.read(object=row_column.object, relation="row_column") == [row_column]

    async def test_write_rejects_conflicts_and_oversized_batches(
        self, store: PermissionStore
    ) -> None:
        item = Tuple("user:1", "member", "group:analysts")
        with pytest.raises(ValueError):
            await store.write(writes=[item], deletes=[item])

        too_many = [
            Tuple(user=f"user:{index}", relation="member", object=f"group:g{index}")
            for index in range(MAX_TUPLES_PER_WRITE + 1)
        ]
        with pytest.raises(ValueError):
            await store.write(writes=too_many)

    async def test_write_rejects_invalid_tuple_atomically(self, store: PermissionStore) -> None:
        valid = Tuple("user:1", "member", "group:analysts")
        invalid = Tuple("user:1", "reader", "db_table:c/s/t")
        with pytest.raises(ValueError):
            await store.write(writes=[valid, invalid])
        assert await store.read() == []

    async def test_write_supports_mixed_writes_and_deletes(self, store: PermissionStore) -> None:
        old = Tuple("user:1", "member", "group:old")
        new = Tuple("user:1", "member", "group:new")
        await store.write(writes=[old])

        await store.write(writes=[new], deletes=[old])

        assert await store.read(object=old.object) == []
        assert await store.read(object=new.object) == [new]

    async def test_read_supports_every_filter_form(self, store: PermissionStore) -> None:
        table_reader = Tuple(
            user="group:analysts#member",
            relation="reader",
            object="db_table:prod/sales/orders",
        )
        row_reader_a = Tuple(
            user="group:analysts#member",
            relation="reader",
            object="row_set:prod/sales/orders/team=a",
        )
        row_reader_b = Tuple(
            user="group:analysts#member",
            relation="reader",
            object="row_set:prod/sales/orders/team=b",
        )
        other_row_reader = Tuple(
            user="group:auditors#member",
            relation="reader",
            object="row_set:prod/sales/orders/team=c",
        )
        parent = Tuple(
            user="db_table:prod/sales/orders",
            relation="table",
            object="row_set:prod/sales/orders/team=a",
        )
        membership = Tuple("user:1", "member", "group:analysts")
        expected = {table_reader, row_reader_a, row_reader_b, other_row_reader, parent, membership}
        await store.write(writes=list(expected))

        assert set(await store.read()) == expected
        assert await store.read(object=table_reader.object) == [table_reader]
        assert await store.read(object=table_reader.object, relation="reader") == [table_reader]
        assert await store.read(object=table_reader.object, user=table_reader.user) == [
            table_reader
        ]
        assert await store.read(
            object=table_reader.object, relation="reader", user=table_reader.user
        ) == [table_reader]
        assert set(
            await store.read(object="row_set:", relation="reader", user="group:analysts#member")
        ) == {row_reader_a, row_reader_b}
        assert await store.read(
            object="row_set:", relation="table", user="db_table:prod/sales/orders"
        ) == [parent]
        assert await store.read(object="row_set:", user="group:auditors#member") == [
            other_row_reader
        ]

    async def test_read_by_type_and_user_for_any_type(self, store: PermissionStore) -> None:
        memberships = {
            Tuple(user="user:7", relation="member", object="group:a"),
            Tuple(user="user:7", relation="member", object="group:b"),
        }
        other = Tuple(user="user:8", relation="member", object="group:a")
        table_rule = Tuple(
            user="group:a#member", relation="reader", object="db_table:prod/sales/orders"
        )
        schema_rule = Tuple(user="group:a#member", relation="reader", object="db_schema:prod/sales")
        await store.write(writes=[*memberships, other, table_rule, schema_rule])

        assert set(await store.read(object="group:", relation="member", user="user:7")) == (
            memberships
        )
        assert await store.read(object="db_table:", user="group:a#member") == [table_rule]
        assert await store.read(object="db_schema:", user="group:a#member") == [schema_rule]

    async def test_read_paginates_all_matching_tuples(self, store: PermissionStore) -> None:
        expected = {
            Tuple(user=f"user:{index}", relation="member", object=f"group:g{index}")
            for index in range(150)
        }
        tuples = list(expected)
        for start in range(0, len(tuples), MAX_TUPLES_PER_WRITE):
            await store.write(writes=tuples[start : start + MAX_TUPLES_PER_WRITE])

        assert set(await store.read()) == expected

    async def test_read_rejects_invalid_filter_combinations(self, store: PermissionStore) -> None:
        invalid_filters = [
            (None, "reader", None),
            (None, None, "user:1"),
            (None, "reader", "user:1"),
            ("row_set:", None, None),
            ("db_table:", None, None),
            ("group:", "member", None),
            ("", None, None),
        ]
        for object_filter, relation, user in invalid_filters:
            with pytest.raises(ValueError):
                await store.read(object=object_filter, relation=relation, user=user)

    async def test_read_changes_order_pagination_and_resume(self, store: PermissionStore) -> None:
        first = Tuple("user:1", "member", "group:first")
        second = Tuple("user:2", "member", "group:second")
        await store.write(writes=[first])
        await store.write(writes=[second])
        await store.write(deletes=[first])

        first_page = await store.read_changes(None, page_size=1)
        empty_token_page = await store.read_changes("", page_size=1)
        assert first_page == empty_token_page
        assert len(first_page.changes) == 1
        assert first_page.changes[0].tuple == first
        assert first_page.changes[0].op is ChangeOp.WRITE
        assert first_page.changes[0].timestamp.tzinfo is not None
        assert first_page.continuation_token

        second_page = await store.read_changes(first_page.continuation_token, page_size=1)
        assert [change.tuple for change in second_page.changes] == [second]
        assert second_page.changes[0].op is ChangeOp.WRITE
        assert second_page.continuation_token != first_page.continuation_token

        final_page = await store.read_changes(second_page.continuation_token, page_size=1)
        assert len(final_page.changes) == 1
        assert final_page.changes[0].tuple == first
        assert final_page.changes[0].op is ChangeOp.DELETE
        assert final_page.continuation_token != second_page.continuation_token

        no_changes = await store.read_changes(final_page.continuation_token, page_size=1)
        assert no_changes.changes == []
        assert no_changes.continuation_token == final_page.continuation_token

    async def test_read_changes_rejects_invalid_tokens(self, store: PermissionStore) -> None:
        for token in ("not-a-token", "999999", "0"):
            with pytest.raises(ContinuationTokenInvalid):
                await store.read_changes(token)

    async def test_read_changes_rejects_page_sizes_outside_openfga_bounds(
        self, store: PermissionStore
    ) -> None:
        for page_size in (0, 101):
            with pytest.raises(ValueError):
                await store.read_changes(None, page_size=page_size)

    async def test_check_supports_direct_and_group_userset_relations(
        self, store: PermissionStore
    ) -> None:
        membership = Tuple("user:1", "member", "group:analysts")
        admin = Tuple("user:1", "admin", "gateway:main")
        parent = Tuple(
            user="db_table:prod/sales/orders",
            relation="table",
            object="row_set:prod/sales/orders/team=a",
        )
        reader = Tuple(
            user="group:analysts#member",
            relation="reader",
            object="db_schema:prod/sales",
        )
        await store.write(writes=[membership, admin, parent, reader])

        assert await store.check("user:1", "member", "group:analysts")
        assert await store.check("user:1", "admin", "gateway:main")
        assert await store.check(
            "db_table:prod/sales/orders", "table", "row_set:prod/sales/orders/team=a"
        )
        assert await store.check("user:1", "reader", "db_schema:prod/sales")
        assert not await store.check("user:2", "reader", "db_schema:prod/sales")

    async def test_check_rejects_unknown_relations(self, store: PermissionStore) -> None:
        with pytest.raises(ValueError):
            await store.check("user:1", "not_a_relation", "group:analysts")


class TestMemoryStore(StoreContract):
    @pytest.fixture
    def store(self) -> PermissionStore:
        return MemoryStore()
