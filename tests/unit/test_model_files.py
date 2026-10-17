import json
import re
from pathlib import Path

type _DirectType = tuple[str, str | None]
type _Relation = tuple[tuple[_DirectType, ...], dict[str, object]]
type _Relations = dict[str, _Relation]
type _Model = dict[str, _Relations]


def _dsl_model(source: str) -> _Model:
    model: _Model = {}
    current_type: str | None = None
    for line in source.splitlines():
        type_match = re.fullmatch(r"\s*type\s+([a-z_]+)\s*", line)
        if type_match is not None:
            matched_type = type_match.group(1)
            if matched_type is None:
                raise AssertionError("type definition must include a type")
            current_type = matched_type
            model[matched_type] = {}
            continue
        relation_match = re.fullmatch(
            r"\s*define\s+([a-z_]+):\s*\[([a-z_]+(?:#[a-z_]+)?)\]\s*", line
        )
        if relation_match is None:
            continue
        if current_type is None:
            raise AssertionError("relation definition appears before a type")
        relation, direct_type = relation_match.groups()
        if relation is None or direct_type is None:
            raise AssertionError("relation definition must include a relation and direct type")
        type_name, separator, userset_relation = direct_type.partition("#")
        direct = (type_name, userset_relation if separator else None)
        model[current_type][relation] = ((direct,), {"this": {}})
    return model


def _json_model(source: str) -> _Model:
    raw = json.loads(source)
    result: _Model = {}
    for definition in raw["type_definitions"]:
        relations: _Relations = {}
        rewrites = definition.get("relations", {})
        metadata = definition.get("metadata", {}).get("relations", {})
        for relation, rewrite in rewrites.items():
            details = metadata.get(relation, {})
            direct_types = details.get("directly_related_user_types", [])
            relations[relation] = (
                tuple(
                    sorted(
                        (
                            direct_type["type"],
                            direct_type.get("relation"),
                        )
                        for direct_type in direct_types
                    )
                ),
                rewrite,
            )
        result[definition["type"]] = relations
    return result


def test_fga_dsl_and_json_have_equivalent_direct_relations() -> None:
    root = Path(__file__).resolve().parents[2]
    permissions = root / "src" / "db_gateway" / "permissions"
    dsl = _dsl_model((permissions / "model.fga").read_text(encoding="utf-8"))
    json_model = _json_model((permissions / "model.json").read_text(encoding="utf-8"))
    assert dsl == json_model
