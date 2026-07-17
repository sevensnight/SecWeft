#!/usr/bin/env python3
"""Validate and snapshot the checked-in P2 OpenAPI contract.

The snapshot is semantic: comments and YAML formatting do not change its digest.
Runtime comparison is intentionally one-way. Every contract operation must exist in
the compatibility runtime, while legacy runtime operations may remain until later
strangler-migration phases remove them.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "packages" / "api-contracts" / "openapi" / "v1.yaml"
SNAPSHOT_PATH = ROOT / "tools" / "contracts" / "snapshots" / "openapi-v1.snapshot.json"
HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
CRITICAL_PATHS = frozenset(
    {
        "/system/requirements",
        "/tasks",
        "/tasks/{task_id}",
        "/tasks/{task_id}/events",
        "/tasks/{task_id}/events/stream",
        "/providers",
        "/providers/health",
        "/providers/{provider_id}/secret",
        "/providers/{provider_id}/enabled",
        "/models/catalog",
        "/models/complete",
        "/models/stream",
        "/models/invocations",
        "/session",
        "/tenants/current",
        "/organizations",
        "/projects",
        "/iam/users",
        "/iam/roles",
        "/iam/role-assignments",
        "/iam/role-assignments/{assignment_id}/revoke",
        "/config/effective",
        "/config/{config_key}",
        "/audit/events",
    }
)
P0_COMPATIBILITY_PATHS = frozenset(
    {
        "/system/requirements",
        "/tasks",
        "/tasks/{task_id}",
        "/tasks/{task_id}/events",
        "/tasks/{task_id}/events/stream",
    }
)
SSE_PATH = "/tasks/{task_id}/events/stream"
MODEL_SSE_PATH = "/models/stream"
FORBIDDEN_PATH_FRAGMENTS = ("/run", "/sandbox", "/assets/probe", "/validation", "/exploit")


class ContractError(RuntimeError):
    """Raised when the signed contract or its runtime projection is invalid."""


def load_document(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise ContractError(f"OpenAPI contract is missing: {path}")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ContractError(f"OpenAPI contract cannot be parsed: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("OpenAPI document root must be an object")
    return value


def iter_operations(document: dict[str, Any]) -> Iterable[tuple[str, str, dict[str, Any]]]:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() in HTTP_METHODS and isinstance(operation, dict):
                yield str(path), method.lower(), operation


def canonical_digest(document: dict[str, Any]) -> str:
    payload = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _response_media_types(operation: dict[str, Any], status: str | None = None) -> list[str]:
    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        return []
    if status is None:
        success = sorted(str(code) for code in responses if str(code).startswith("2"))
        status = success[0] if success else "200"
    response = responses.get(status, responses.get(int(status)) if status.isdigit() else None)
    if not isinstance(response, dict):
        return []
    content = response.get("content", {})
    return sorted(str(media_type) for media_type in content) if isinstance(content, dict) else []


def _snapshot_parameters(operation: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep transport-significant parameters in the semantic review artifact."""
    result: list[dict[str, Any]] = []
    parameters = operation.get("parameters", [])
    if not isinstance(parameters, list):
        return result
    for item in parameters:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("$ref"), str):
            result.append({"ref": item["$ref"]})
            continue
        result.append(
            {
                "name": item.get("name"),
                "in": item.get("in"),
                "required": bool(item.get("required", False)),
            }
        )
    return sorted(result, key=lambda item: json.dumps(item, sort_keys=True))


def build_snapshot(document: dict[str, Any]) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    for path, method, operation in iter_operations(document):
        responses = operation.get("responses", {})
        operations.append(
            {
                "method": method.upper(),
                "path": path,
                "operation_id": operation.get("operationId"),
                "parameters": _snapshot_parameters(operation),
                "responses": sorted(str(code) for code in responses)
                if isinstance(responses, dict)
                else [],
                "success_media_types": _response_media_types(operation),
            }
        )
    schemas = document.get("components", {}).get("schemas", {})
    info = document.get("info", {})
    return {
        "contract": "packages/api-contracts/openapi/v1.yaml",
        "document_sha256": canonical_digest(document),
        "openapi": document.get("openapi"),
        "info_version": info.get("version") if isinstance(info, dict) else None,
        "operations": sorted(operations, key=lambda item: (item["path"], item["method"])),
        "schemas": sorted(schemas) if isinstance(schemas, dict) else [],
    }


def _parameter_refs(operation: dict[str, Any]) -> set[str]:
    parameters = operation.get("parameters", [])
    if not isinstance(parameters, list):
        return set()
    return {
        str(item.get("$ref"))
        for item in parameters
        if isinstance(item, dict) and isinstance(item.get("$ref"), str)
    }


def validate_document(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("openapi") != "3.1.0":
        errors.append("openapi must be exactly 3.1.0")
    info = document.get("info")
    if not isinstance(info, dict) or not all(info.get(key) for key in ("title", "version")):
        errors.append("info.title and info.version are required")
    servers = document.get("servers")
    if not isinstance(servers, list) or "/api/v1" not in {
        item.get("url") for item in servers if isinstance(item, dict)
    }:
        errors.append("servers must declare the /api/v1 version prefix")

    components = document.get("components")
    if not isinstance(components, dict):
        errors.append("components must be an object")
        components = {}
    schemes = components.get("securitySchemes", {})
    api_key = schemes.get("ApiKeyAuth", {}) if isinstance(schemes, dict) else {}
    if not isinstance(api_key, dict) or {
        "type": api_key.get("type"),
        "in": api_key.get("in"),
        "name": api_key.get("name"),
    } != {"type": "apiKey", "in": "header", "name": "X-API-Key"}:
        errors.append("ApiKeyAuth must be the documented compatibility X-API-Key header scheme")
    bearer = schemes.get("BearerAuth", {}) if isinstance(schemes, dict) else {}
    if not isinstance(bearer, dict) or {
        "type": bearer.get("type"),
        "scheme": bearer.get("scheme"),
        "bearerFormat": bearer.get("bearerFormat"),
    } != {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}:
        errors.append("BearerAuth must be the documented OIDC JWT bearer scheme")
    if {"ApiKeyAuth": []} not in document.get("security", []):
        errors.append("the P0 contract must default to authenticated operations")

    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        errors.append("paths must be a non-empty object")
        paths = {}
    missing = sorted(CRITICAL_PATHS - set(paths))
    if missing:
        errors.append(f"critical P0 paths are missing: {', '.join(missing)}")
    for path in paths:
        if not isinstance(path, str) or not path.startswith("/"):
            errors.append(f"invalid path key: {path!r}")
        if isinstance(path, str) and path.startswith("/api/v1"):
            errors.append(f"path duplicates the server version prefix: {path}")
        if any(fragment in str(path).lower() for fragment in FORBIDDEN_PATH_FRAGMENTS):
            errors.append(f"P1 contract exposes a deferred execution capability: {path}")

    operation_ids: set[str] = set()
    operation_count = 0
    for path, method, operation in iter_operations(document):
        operation_count += 1
        if path in P0_COMPATIBILITY_PATHS and method != "get":
            errors.append(
                f"P0 compatibility contract must remain read-only: {method.upper()} {path}"
            )
        if path not in P0_COMPATIBILITY_PATHS and method not in {"get", "post", "put"}:
            errors.append(f"P1 contract uses an unsupported method: {method.upper()} {path}")
        operation_id = operation.get("operationId")
        if not isinstance(operation_id, str) or not operation_id:
            errors.append(f"operationId is required for {method.upper()} {path}")
        elif operation_id in operation_ids:
            errors.append(f"operationId is duplicated: {operation_id}")
        else:
            operation_ids.add(operation_id)
        responses = operation.get("responses")
        response_codes = {str(key) for key in responses} if isinstance(responses, dict) else set()
        if not any(code.startswith("2") for code in response_codes):
            errors.append(f"successful response is missing for {method.upper()} {path}")
        if not isinstance(responses, dict) or "401" not in {str(key) for key in responses}:
            errors.append(f"401 response is missing for {method.upper()} {path}")
        if "#/components/parameters/XRequestId" not in _parameter_refs(operation):
            errors.append(f"X-Request-ID parameter is missing for {method.upper()} {path}")
        if path not in P0_COMPATIBILITY_PATHS and {"BearerAuth": []} not in operation.get(
            "security", []
        ):
            errors.append(f"OIDC BearerAuth is missing for {method.upper()} {path}")
        if method in {"post", "put"} and (
            "#/components/parameters/IdempotencyKey" not in _parameter_refs(operation)
        ):
            errors.append(f"Idempotency-Key is missing for {method.upper()} {path}")
    if operation_count == 0:
        errors.append("the contract has no operations")

    sse_path_item = paths.get(SSE_PATH, {}) if isinstance(paths, dict) else {}
    sse = sse_path_item.get("get", {}) if isinstance(sse_path_item, dict) else {}
    if isinstance(sse, dict):
        if _response_media_types(sse) != ["text/event-stream"]:
            errors.append(f"GET {SSE_PATH} must return only text/event-stream for response 200")
        last_event_id = next(
            (
                item
                for item in sse.get("parameters", [])
                if isinstance(item, dict) and item.get("name") == "Last-Event-ID"
            ),
            None,
        )
        if not isinstance(last_event_id, dict) or last_event_id.get("in") != "header":
            errors.append(f"GET {SSE_PATH} must declare the Last-Event-ID request header")
        else:
            schema = last_event_id.get("schema", {})
            if (
                not isinstance(schema, dict)
                or schema.get("type") != "integer"
                or schema.get("minimum") != 0
            ):
                errors.append("Last-Event-ID must be a non-negative integer")

    model_stream = paths.get(MODEL_SSE_PATH, {}).get("post", {}) if isinstance(paths, dict) else {}
    if isinstance(model_stream, dict) and _response_media_types(model_stream) != [
        "text/event-stream"
    ]:
        errors.append(f"POST {MODEL_SSE_PATH} must return only text/event-stream for response 200")

    schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
    for required_schema in (
        "Problem",
        "SystemRequirements",
        "Task",
        "TaskEvent",
        "Session",
        "Tenant",
        "Organization",
        "Project",
        "User",
        "Role",
        "RoleAssignment",
        "ConfigEntry",
        "AuditEvent",
        "ModelProvider",
        "ModelProviderCreate",
        "ModelProviderHealth",
        "ModelCatalogItem",
        "ModelCompletionRequest",
        "ModelCompletion",
        "ModelInvocation",
        "ModelUsage",
        "ModelToolDefinition",
    ):
        if not isinstance(schemas, dict) or required_schema not in schemas:
            errors.append(f"components.schemas.{required_schema} is required")
    problem = schemas.get("Problem", {}) if isinstance(schemas, dict) else {}
    if problem.get("additionalProperties") is not False:
        errors.append("Problem must reject unknown fields")
    required_problem_fields = {"detail", "code", "request_id", "trace_id"}
    if not required_problem_fields <= set(problem.get("required", [])):
        errors.append("Problem must require detail, code, request_id, and trace_id")
    return errors


def _runtime_document() -> dict[str, Any]:
    source_root = ROOT / "apps" / "control-plane" / "src"
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    from vulnlab.app import create_app
    from vulnlab.config import Settings

    master = base64.urlsafe_b64encode(hashlib.sha256(b"p0-contract-runtime").digest()).decode()
    with tempfile.TemporaryDirectory(prefix="vulnlab-contract-") as temp:
        temp_root = Path(temp)
        settings = Settings(
            env="test",
            db_path=temp_root / "runtime.db",
            workspace_root=temp_root / "workspaces",
            admin_key="p0-contract-admin-key-with-entropy",
            master_key=master,
            execution_mode="dry_run",
            allowed_hosts=("localhost", "127.0.0.1", "::1"),
            allowed_ports=(80, 443),
            legacy_execution_enabled=False,
        )
        return create_app(settings).openapi()


def validate_runtime_projection(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    runtime = _runtime_document()
    runtime_paths = runtime.get("paths", {})
    for path, method, _ in iter_operations(contract):
        runtime_path = "/api/v1" + path
        runtime_item = runtime_paths.get(runtime_path) if isinstance(runtime_paths, dict) else None
        if not isinstance(runtime_item, dict) or method not in runtime_item:
            errors.append(
                f"runtime is missing contracted operation {method.upper()} {runtime_path}"
            )
    runtime_sse = (
        runtime_paths.get("/api/v1" + SSE_PATH, {}).get("get", {})
        if isinstance(runtime_paths, dict)
        else {}
    )
    runtime_sse_parameters = (
        runtime_sse.get("parameters", []) if isinstance(runtime_sse, dict) else []
    )
    if not any(
        isinstance(item, dict)
        and item.get("name") == "Last-Event-ID"
        and item.get("in") == "header"
        for item in runtime_sse_parameters
    ):
        errors.append("runtime SSE operation is missing the Last-Event-ID request header")
    return errors


def load_snapshot(path: Path = SNAPSHOT_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise ContractError(f"OpenAPI semantic snapshot is missing: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"OpenAPI semantic snapshot cannot be parsed: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("OpenAPI semantic snapshot root must be an object")
    return value


def check(*, runtime: bool = False) -> dict[str, Any]:
    document = load_document()
    errors = validate_document(document)
    expected = build_snapshot(document)
    try:
        actual = load_snapshot()
    except ContractError as exc:
        errors.append(str(exc))
        actual = None
    if actual is not None and actual != expected:
        errors.append(
            "OpenAPI semantic snapshot differs from the contract; review the API change and run "
            "openapi_snapshot.py snapshot only after approval"
        )
    if runtime:
        errors.extend(validate_runtime_projection(document))
    return {
        "valid": not errors,
        "contract": str(CONTRACT_PATH.relative_to(ROOT)).replace("\\", "/"),
        "snapshot": str(SNAPSHOT_PATH.relative_to(ROOT)).replace("\\", "/"),
        "runtime_checked": runtime,
        "operation_count": len(list(iter_operations(document))),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OpenAPI P2 semantic snapshot and compatibility checker"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    check_parser = subcommands.add_parser(
        "check", help="validate source, snapshot, and optional runtime projection"
    )
    check_parser.add_argument(
        "--runtime", action="store_true", help="also compare contracted operations to FastAPI"
    )
    snapshot_parser = subcommands.add_parser(
        "snapshot", help="emit or intentionally update the semantic snapshot"
    )
    snapshot_parser.add_argument(
        "--write", action="store_true", help="write the reviewed snapshot to its signed path"
    )
    args = parser.parse_args()

    if args.command == "snapshot":
        document = load_document()
        errors = validate_document(document)
        if errors:
            print(json.dumps({"valid": False, "errors": errors}, ensure_ascii=False, indent=2))
            return 1
        value = build_snapshot(document)
        rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        if args.write:
            SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
            SNAPSHOT_PATH.write_text(rendered, encoding="utf-8", newline="\n")
        else:
            print(rendered, end="")
        return 0

    result = check(runtime=args.runtime)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
