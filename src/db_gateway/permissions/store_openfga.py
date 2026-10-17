"""OpenFGA-backed permission store.

The OpenFGA SDK is intentionally confined to this module.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC
from pathlib import Path
from typing import Any, cast

import aiohttp
from openfga_sdk.client import ClientConfiguration, OpenFgaClient
from openfga_sdk.client.models import (
    ClientReadChangesRequest,
    ClientTuple,
    ClientWriteRequest,
    ClientWriteRequestOnDuplicateWrites,
    ClientWriteRequestOnMissingDeletes,
    ConflictOptions,
)
from openfga_sdk.client.models.check_request import ClientCheckRequest
from openfga_sdk.exceptions import ApiException
from openfga_sdk.models import ReadRequestTupleKey, WriteAuthorizationModelRequest
from openfga_sdk.models.tuple_operation import TupleOperation

from db_gateway.permissions.store import (
    MAX_TUPLES_PER_WRITE,
    Change,
    ChangeOp,
    ChangesPage,
    ContinuationTokenInvalid,
    PermissionStoreUnavailable,
    Tuple,
)
from db_gateway.settings import Settings

_MODEL_PATH = Path(__file__).with_name("model.json")


def _as_tuple(key: Any) -> Tuple:
    return Tuple(user=key.user, relation=key.relation, object=key.object)


def _plain(value: Any) -> Any:
    """Convert SDK objects to dictionaries while dropping absent fields."""
    if hasattr(value, "to_dict"):
        value = value.to_dict(serialize=True)
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_plain(item) for item in value]
    return value


def _normalized_model(model: Any) -> dict[str, Any]:
    """Compare model semantics without SDK-added empty defaults or model IDs."""
    model = _plain(model)
    definitions = []
    for definition in model.get("type_definitions", []):
        relations = definition.get("relations") or {}
        metadata = (definition.get("metadata") or {}).get("relations") or {}
        direct_types = {}
        for relation, details in metadata.items():
            restrictions = []
            for restriction in details.get("directly_related_user_types", []):
                normalized = {"type": restriction["type"]}
                for field in ("relation", "condition"):
                    value = restriction.get(field)
                    if value not in (None, ""):
                        normalized[field] = value
                restrictions.append(normalized)
            direct_types[relation] = sorted(
                restrictions, key=lambda restriction: json.dumps(restriction, sort_keys=True)
            )
        definitions.append(
            {
                "type": definition["type"],
                "relations": relations,
                "directly_related_user_types": direct_types,
            }
        )
    return {
        "schema_version": model.get("schema_version"),
        "type_definitions": sorted(definitions, key=lambda definition: definition["type"]),
        "conditions": model.get("conditions") or {},
    }


def _error_code(exc: ApiException) -> str | None:
    if exc.code is not None:
        return str(exc.code)
    if not isinstance(exc.body, str):
        return None
    try:
        body = json.loads(exc.body)
    except json.JSONDecodeError:
        return None
    code = body.get("code") if isinstance(body, dict) else None
    return code if isinstance(code, str) else None


class PermissionStoreMisconfigured(Exception):
    """OpenFGA rejected the configured credentials or store permissions."""


class OpenFgaStore:
    """PermissionStore implementation using an asynchronous OpenFGA client."""

    def __init__(self, api_url: str, store_id: str, model_id: str | None = None) -> None:
        self._model_id = model_id
        self._client = OpenFgaClient(
            ClientConfiguration(
                api_url=api_url.rstrip("/"),
                store_id=store_id,
                authorization_model_id=model_id,
            )
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> OpenFgaStore:
        if settings.openfga_store_id is None:
            raise ValueError("openfga_store_id must be configured")
        return cls(
            api_url=settings.openfga_api_url,
            store_id=settings.openfga_store_id,
            model_id=settings.openfga_model_id,
        )

    async def _request(self, request: Any, *, changes: bool = False) -> Any:
        try:
            return await request
        except ApiException as exc:
            code = _error_code(exc)
            if changes and exc.status == 400 and code == "invalid_continuation_token":
                raise ContinuationTokenInvalid(str(exc)) from exc
            if exc.status == 400 and code == "validation_error":
                raise ValueError(str(exc)) from exc
            if exc.status in (401, 403):
                raise PermissionStoreMisconfigured(
                    f"OpenFGA rejected its configured credentials or permissions: {exc}"
                ) from exc
            if exc.status == 429 or (exc.status is not None and 500 <= exc.status <= 599):
                raise PermissionStoreUnavailable(str(exc)) from exc
            raise
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:
            raise PermissionStoreUnavailable(str(exc)) from exc

    async def ensure_model(self) -> str:
        """Install the bundled model if it differs from the store's latest model."""
        expected = json.loads(_MODEL_PATH.read_text(encoding="utf-8"))
        latest = await self._request(self._client.read_latest_authorization_model())
        current = latest.authorization_model
        if current is not None and _normalized_model(current) == _normalized_model(expected):
            model_id = current.id
        else:
            written = await self._request(
                self._client.write_authorization_model(
                    WriteAuthorizationModelRequest(
                        schema_version=expected["schema_version"],
                        type_definitions=expected["type_definitions"],
                    )
                )
            )
            model_id = written.authorization_model_id
        self._model_id = model_id
        return model_id

    async def write(self, writes: Sequence[Tuple] = (), deletes: Sequence[Tuple] = ()) -> None:
        if set(writes).intersection(deletes):
            raise ValueError("the same tuple cannot be written and deleted")
        if len(writes) + len(deletes) > MAX_TUPLES_PER_WRITE:
            raise ValueError(f"at most {MAX_TUPLES_PER_WRITE} tuples may be written at once")
        if not writes and not deletes:
            return

        options: dict[str, Any] = {
            "conflict": ConflictOptions(
                on_duplicate_writes=ClientWriteRequestOnDuplicateWrites.IGNORE,
                on_missing_deletes=ClientWriteRequestOnMissingDeletes.IGNORE,
            )
        }
        if self._model_id is not None:
            options["authorization_model_id"] = self._model_id
        await self._request(
            self._client.write(
                ClientWriteRequest(
                    writes=[
                        ClientTuple(user=item.user, relation=item.relation, object=item.object)
                        for item in writes
                    ],
                    deletes=[
                        ClientTuple(user=item.user, relation=item.relation, object=item.object)
                        for item in deletes
                    ],
                ),
                options,
            )
        )

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

        key = ReadRequestTupleKey(user=user, relation=relation, object=object)
        result: list[Tuple] = []
        continuation_token: str | None = None
        while True:
            options: dict[str, Any] = {"page_size": MAX_TUPLES_PER_WRITE}
            if continuation_token:
                options["continuation_token"] = continuation_token
            page = await self._request(self._client.read(key, options))
            result.extend(_as_tuple(item.key) for item in page.tuples)
            continuation_token = page.continuation_token
            if not continuation_token:
                return result

    async def read_changes(
        self, continuation_token: str | None, page_size: int = 100
    ) -> ChangesPage:
        if not 1 <= page_size <= 100:
            raise ValueError("page_size must be between 1 and 100")
        # The SDK types this API's optional type filter as required; None means no filter.
        request = ClientReadChangesRequest(type=cast(str, None))
        options: dict[str, Any] = {"page_size": page_size}
        if continuation_token:
            options["continuation_token"] = continuation_token
        response = await self._request(self._client.read_changes(request, options), changes=True)
        changes = []
        for item in response.changes:
            timestamp = item.timestamp
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
            if item.operation == TupleOperation.WRITE:
                operation = ChangeOp.WRITE
            elif item.operation == TupleOperation.DELETE:
                operation = ChangeOp.DELETE
            else:
                raise ValueError(f"unknown OpenFGA tuple operation: {item.operation!r}")
            changes.append(
                Change(tuple=_as_tuple(item.tuple_key), op=operation, timestamp=timestamp)
            )
        return ChangesPage(
            changes=changes,
            continuation_token=response.continuation_token or "",
        )

    async def check(self, user: str, relation: str, object: str) -> bool:
        options: dict[str, Any] = {}
        if self._model_id is not None:
            options["authorization_model_id"] = self._model_id
        response = await self._request(
            self._client.check(
                ClientCheckRequest(user=user, relation=relation, object=object), options
            )
        )
        return response.allowed

    async def aclose(self) -> None:
        await self._client.close()
