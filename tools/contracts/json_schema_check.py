#!/usr/bin/env python3
"""Dependency-light checks for the JSON Schema 2020-12 P0 contracts."""

from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "packages" / "api-contracts"
SCHEMA_PATHS = (
    CONTRACT_ROOT / "events" / "task-event.v1.schema.json",
    CONTRACT_ROOT / "protocol" / "domain-protocol.v1.schema.json",
)
VALID_TYPES = frozenset({"null", "boolean", "object", "array", "number", "string", "integer"})


class SchemaValidationError(ValueError):
    """Raised when a schema or sample instance violates the supported contract subset."""


def load_schema(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SchemaValidationError(f"schema is missing: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaValidationError(f"schema cannot be parsed: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SchemaValidationError(f"schema root must be an object: {path}")
    return value


def resolve_pointer(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise SchemaValidationError(f"only local JSON pointers are permitted in P0: {reference}")
    current: Any = root
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise SchemaValidationError(f"unresolved JSON pointer: {reference}")
        current = current[part]
    if not isinstance(current, dict):
        raise SchemaValidationError(
            f"JSON pointer does not resolve to a schema object: {reference}"
        )
    return current


def _is_type(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    return False


def _validate_format(value: str, format_name: str, path: str) -> None:
    try:
        if format_name == "uuid":
            uuid.UUID(value)
        elif format_name == "date-time":
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timezone is required")
        elif format_name == "uri":
            parsed_uri = urlsplit(value)
            if not parsed_uri.scheme:
                raise ValueError("URI scheme is required")
    except (ValueError, AttributeError) as exc:
        raise SchemaValidationError(f"{path} is not a valid {format_name}") from exc


def validate_instance(
    schema: dict[str, Any],
    value: Any,
    *,
    root: dict[str, Any] | None = None,
    path: str = "$",
) -> None:
    root = root or schema
    if "$ref" in schema:
        validate_instance(resolve_pointer(root, str(schema["$ref"])), value, root=root, path=path)
        return
    if "oneOf" in schema:
        alternatives = schema["oneOf"]
        if not isinstance(alternatives, list) or not alternatives:
            raise SchemaValidationError(f"{path}: oneOf must be a non-empty array")
        matched = 0
        for alternative in alternatives:
            if not isinstance(alternative, dict):
                continue
            try:
                validate_instance(alternative, value, root=root, path=path)
            except SchemaValidationError:
                continue
            matched += 1
        if matched != 1:
            raise SchemaValidationError(f"{path} must match exactly one schema, matched {matched}")
        return

    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{path} must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError(f"{path} is not one of the allowed values")
    declared_type = schema.get("type")
    if declared_type is not None:
        expected_types = declared_type if isinstance(declared_type, list) else [declared_type]
        if not expected_types or any(item not in VALID_TYPES for item in expected_types):
            raise SchemaValidationError(
                f"{path}: invalid schema type declaration {declared_type!r}"
            )
        if not any(_is_type(value, item) for item in expected_types):
            raise SchemaValidationError(f"{path} has the wrong type; expected {expected_types}")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise SchemaValidationError(f"{path}: properties must be an object")
        required = schema.get("required", [])
        if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
            raise SchemaValidationError(f"{path}: required must be an array of strings")
        missing = [key for key in required if key not in value]
        if missing:
            raise SchemaValidationError(f"{path} lacks required properties: {', '.join(missing)}")
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if key in properties:
                child_schema = properties[key]
                if not isinstance(child_schema, dict):
                    raise SchemaValidationError(f"{child_path}: property schema must be an object")
                validate_instance(child_schema, item, root=root, path=child_path)
            elif additional is False:
                raise SchemaValidationError(f"{child_path} is not allowed")
            elif isinstance(additional, dict):
                validate_instance(additional, item, root=root, path=child_path)

    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(value) < minimum:
            raise SchemaValidationError(f"{path} has fewer than {minimum} items")
        if isinstance(maximum, int) and len(value) > maximum:
            raise SchemaValidationError(f"{path} has more than {maximum} items")
        if schema.get("uniqueItems") is True:
            canonical = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(canonical) != len(set(canonical)):
                raise SchemaValidationError(f"{path} contains duplicate items")
        items_schema = schema.get("items")
        if isinstance(items_schema, dict):
            for index, item in enumerate(value):
                validate_instance(items_schema, item, root=root, path=f"{path}[{index}]")

    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if isinstance(minimum, int) and len(value) < minimum:
            raise SchemaValidationError(f"{path} is shorter than {minimum}")
        if isinstance(maximum, int) and len(value) > maximum:
            raise SchemaValidationError(f"{path} is longer than {maximum}")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            raise SchemaValidationError(f"{path} does not match {pattern!r}")
        format_name = schema.get("format")
        if isinstance(format_name, str):
            _validate_format(value, format_name, path)

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            raise SchemaValidationError(f"{path} is less than {minimum}")
        if isinstance(maximum, (int, float)) and value > maximum:
            raise SchemaValidationError(f"{path} is greater than {maximum}")


def _walk_schema(schema: Any, root: dict[str, Any], path: str, errors: list[str]) -> None:
    if isinstance(schema, list):
        for index, item in enumerate(schema):
            _walk_schema(item, root, f"{path}[{index}]", errors)
        return
    if not isinstance(schema, dict):
        return
    if path.endswith(".properties") or path.endswith(".$defs"):
        for key, item in schema.items():
            _walk_schema(item, root, f"{path}.{key}", errors)
        return
    reference = schema.get("$ref")
    if isinstance(reference, str):
        try:
            resolve_pointer(root, reference)
        except SchemaValidationError as exc:
            errors.append(f"{path}: {exc}")
    declared_type = schema.get("type")
    types = declared_type if isinstance(declared_type, list) else [declared_type]
    if declared_type is not None and (not types or any(item not in VALID_TYPES for item in types)):
        errors.append(f"{path}: invalid type declaration {declared_type!r}")
    required = schema.get("required")
    properties = schema.get("properties")
    if isinstance(required, list) and isinstance(properties, dict):
        unknown = sorted(set(required) - set(properties))
        if unknown:
            errors.append(f"{path}: required keys have no property schema: {', '.join(unknown)}")
    for key, item in schema.items():
        if key not in {"examples", "default", "const", "enum"}:
            _walk_schema(item, root, f"{path}.{key}", errors)


def check() -> dict[str, Any]:
    errors: list[str] = []
    schema_ids: set[str] = set()
    checked: list[str] = []
    for path in SCHEMA_PATHS:
        try:
            schema = load_schema(path)
        except SchemaValidationError as exc:
            errors.append(str(exc))
            continue
        relative = str(path.relative_to(ROOT)).replace("\\", "/")
        checked.append(relative)
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{relative}: $schema must select JSON Schema draft 2020-12")
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id.startswith("https://"):
            errors.append(f"{relative}: a stable HTTPS $id is required")
        elif schema_id in schema_ids:
            errors.append(f"{relative}: duplicated $id {schema_id}")
        else:
            schema_ids.add(schema_id)
        if not isinstance(schema.get("title"), str) or not schema["title"]:
            errors.append(f"{relative}: title is required")
        _walk_schema(schema, schema, "$", errors)
        try:
            import jsonschema

            jsonschema.Draft202012Validator.check_schema(schema)
        except ImportError:
            pass
        except Exception as exc:
            errors.append(f"{relative}: official meta-schema validation failed: {exc}")
    return {"valid": not errors, "schemas": checked, "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate signed JSON Schema 2020-12 contracts")
    parser.parse_args()
    result = check()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
