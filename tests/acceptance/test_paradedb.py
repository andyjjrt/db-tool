"""Plan §5 ParadeDB: `@@@` and `paradedb.score()` on a row-controlled table."""

from psycopg.sql import SQL

from tests.acceptance.conftest import CONNECTION, Person, Stack


async def _searchable_world(stack: Stack) -> dict[str, tuple[Person, list[int]]]:
    """Users with the ids a plain `@@@ 'apple'` search must return for each."""
    only_a = await stack.new_user()
    only_b = await stack.new_user()
    nobody = await stack.new_user()
    reader = await stack.new_user()
    group_a = await stack.new_group("pa", only_a)
    group_b = await stack.new_group("pb", only_b)
    group_all = await stack.new_group("pall", reader)
    await stack.new_group("pn", nobody)
    async with await stack.connect(CONNECTION) as conn:
        await conn.execute(
            SQL(
                "CREATE INDEX items_bm25 ON {} USING bm25 (id, team, body) WITH (key_field='id')"
            ).format(stack.rel())
        )
    await stack.declare()
    await stack.row_set(group_a, "a")
    await stack.row_set(group_b, "b")
    await stack.rules.grant_table_reader(stack.actor, group_all, CONNECTION, stack.schema, "items")
    await stack.sync()
    return {
        "a": (only_a, [1, 2]),
        "b": (only_b, [3]),
        "none": (nobody, []),
        "table_reader": (reader, [1, 2, 3]),
    }


async def _ids(stack: Stack, person: Person, term: str) -> list[int]:
    async with await stack.connect_as(person.login) as conn:
        cursor = await conn.execute(
            SQL("SELECT id FROM {} WHERE body @@@ %s ORDER BY id").format(stack.rel()), (term,)
        )
        return [row[0] for row in await cursor.fetchall()]


async def test_s5_paradedb_search_operator_returns_only_allowed_rows(stack: Stack) -> None:
    """§5 ParadeDB: `@@@` on a row-controlled table returns only the reader's rows."""
    world = await _searchable_world(stack)
    for name, (person, expected) in world.items():
        assert await _ids(stack, person, "apple") == expected, name
    # A term matching only a team-c row reaches nobody but the table reader.
    assert await _ids(stack, world["a"][0], "banana") == []
    assert await _ids(stack, world["b"][0], "banana") == []
    assert await _ids(stack, world["none"][0], "banana") == []
    assert await _ids(stack, world["table_reader"][0], "banana") == [4]


async def test_s5_paradedb_score_returns_only_allowed_rows(stack: Stack) -> None:
    """§5 ParadeDB: `paradedb.score()` on a row-controlled table returns only the reader's rows."""
    world = await _searchable_world(stack)
    # Row visibility is asserted without scoring first, so a leak is a plain failure.
    for name, (person, expected) in world.items():
        assert await _ids(stack, person, "apple") == expected, name
    query = SQL("SELECT id, paradedb.score(id) FROM {} WHERE body @@@ 'apple' ORDER BY id").format(
        stack.rel()
    )
    for name, (person, expected) in world.items():
        async with await stack.connect_as(person.login) as conn:
            rows = await (await conn.execute(query)).fetchall()
        assert [r[0] for r in rows] == expected, name
        assert all(r[1] is not None and r[1] > 0 for r in rows), name
