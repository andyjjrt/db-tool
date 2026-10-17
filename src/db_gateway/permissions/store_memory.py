"""In-memory PermissionStore implementation for tests."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from db_gateway.permissions.store import (
    MAX_TUPLES_PER_WRITE,
    Change,
    ChangeOp,
    ChangesPage,
    ContinuationTokenInvalid,
    Tuple,
)

_MODEL_PATH = Path(__file__).with_name("model.json")
_MAX_PAGE_SIZE = 100


class MemoryStore:
    """Deterministic in-memory implementation of the permission store contract."""

    def __init__(self) -> None:
        model = json.loads(_MODEL_PATH.read_text(encoding="utf-8"))
        self._types: dict[str, dict[str, Any]] = {
            definition["type"]: definition for definition in model["type_definitions"]
        }
        self._tuples: set[Tuple] = set()
        self._changes: list[tuple[int, Change]] = []

    def _parse_identifier(self, identifier: str) -> tuple[str, str | None]:
        object_id, separator, relation = identifier.partition("#")
        type_name, type_separator, resource_id = object_id.partition(":")
        if (
            not type_separator
            or not type_name
            or not resource_id
            or (separator and (not relation or "#" in relation))
        ):
            raise ValueError(f"malformed OpenFGA identifier: {identifier!r}")
        return type_name, relation if separator else None

    def _validate_tuple(self, item: Tuple) -> None:
        object_type, object_relation = self._parse_identifier(item.object)
        if object_relation is not None:
            raise ValueError(f"tuple object must be an object, not a userset: {item.object!r}")
        definition = self._types.get(object_type)
        if definition is None:
            raise ValueError(f"unknown object type: {object_type!r}")
        if item.relation not in definition.get("relations", {}):
            raise ValueError(f"unknown relation {item.relation!r} on {object_type!r}")

        user_type, user_relation = self._parse_identifier(item.user)
        if user_type not in self._types:
            raise ValueError(f"unknown user type: {user_type!r}")
        relation_metadata = (
            definition.get("metadata", {}).get("relations", {}).get(item.relation, {})
        )
        allowed_users = relation_metadata.get("directly_related_user_types", [])
        if not any(
            allowed.get("type") == user_type and allowed.get("relation") == user_relation
            for allowed in allowed_users
        ):
            raise ValueError(f"user {item.user!r} is not allowed for {object_type}#{item.relation}")

    def _validate_check(self, user: str, relation: str, object: str) -> None:
        object_type, object_relation = self._parse_identifier(object)
        definition = self._types.get(object_type)
        if object_relation is not None or definition is None:
            raise ValueError(f"unknown object: {object!r}")
        if relation not in definition.get("relations", {}):
            raise ValueError(f"unknown relation {relation!r} on {object_type!r}")

        user_type, user_relation = self._parse_identifier(user)
        user_definition = self._types.get(user_type)
        if user_definition is None:
            raise ValueError(f"unknown user type: {user_type!r}")
        if user_relation is not None and user_relation not in user_definition.get("relations", {}):
            raise ValueError(f"unknown userset relation {user_type}#{user_relation}")

    async def write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
        if set(writes).intersection(deletes):
            raise ValueError("the same tuple cannot be written and deleted")
        if len(writes) + len(deletes) > MAX_TUPLES_PER_WRITE:
            raise ValueError(f"at most {MAX_TUPLES_PER_WRITE} tuples may be written at once")
        for item in (*writes, *deletes):
            self._validate_tuple(item)

        timestamp = datetime.now(UTC)
        for item in writes:
            if item not in self._tuples:
                self._tuples.add(item)
                self._append_change(item, ChangeOp.WRITE, timestamp)
        for item in deletes:
            if item in self._tuples:
                self._tuples.remove(item)
                self._append_change(item, ChangeOp.DELETE, timestamp)

    def _append_change(self, item: Tuple, operation: ChangeOp, timestamp: datetime) -> None:
        sequence = len(self._changes) + 1
        self._changes.append((sequence, Change(item, operation, timestamp)))

    async def read(
        self, object: str | None = None, relation: str | None = None, user: str | None = None
    ) -> list[Tuple]:
        if object is None:
            if relation is not None or user is not None:
                raise ValueError("relation and user filters require an object")
        elif not object or (object.endswith(":") and object != "row_set:"):
            raise ValueError("only row_set: is supported as a type-only object filter")
        elif object == "row_set:" and user is None:
            raise ValueError("a user filter is required for row_set:")

        result = self._tuples
        if object == "row_set:":
            result = {item for item in result if item.object.startswith("row_set:")}
        elif object is not None:
            result = {item for item in result if item.object == object}
        if relation is not None:
            result = {item for item in result if item.relation == relation}
        if user is not None:
            result = {item for item in result if item.user == user}
        return sorted(result, key=lambda item: (item.object, item.relation, item.user))

    async def read_changes(
        self, continuation_token: str | None, page_size: int = 100
    ) -> ChangesPage:
        if not 1 <= page_size <= _MAX_PAGE_SIZE:
            raise ValueError("page_size must be between 1 and 100")

        if continuation_token in (None, ""):
            cursor = 0
        else:
            try:
                cursor = int(continuation_token)
            except ValueError as exc:
                raise ContinuationTokenInvalid("malformed continuation token") from exc
            if str(cursor) != continuation_token or cursor < 1 or cursor > len(self._changes):
                raise ContinuationTokenInvalid("unknown continuation token")

        page = [change for sequence, change in self._changes if sequence > cursor][:page_size]
        if page:
            next_token = str(cursor + len(page))
        else:
            next_token = continuation_token or ""
        return ChangesPage(changes=page, continuation_token=next_token)

    async def check(self, user: str, relation: str, object: str) -> bool:
        self._validate_check(user, relation, object)
        if Tuple(user=user, relation=relation, object=object) in self._tuples:
            return True

        for item in self._tuples:
            if item.object != object or item.relation != relation:
                continue
            group_id, separator, group_relation = item.user.partition("#")
            if (
                separator
                and group_id.startswith("group:")
                and group_relation == "member"
                and Tuple(user=user, relation="member", object=group_id) in self._tuples
            ):
                return True
        return False
