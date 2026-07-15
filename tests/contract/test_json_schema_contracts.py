from __future__ import annotations

from copy import deepcopy

import pytest

from tools.contracts.json_schema_check import (
    SCHEMA_PATHS,
    SchemaValidationError,
    check,
    load_schema,
    validate_instance,
)

TENANT_ID = "11111111-1111-4111-8111-111111111111"
PROJECT_ID = "22222222-2222-4222-8222-222222222222"
USER_ID = "33333333-3333-4333-8333-333333333333"
TASK_ID = "44444444-4444-4444-8444-444444444444"


def valid_task_event() -> dict:
    return {
        "specversion": "1.0",
        "id": "55555555-5555-4555-8555-555555555555",
        "source": "vulnlab.control-plane",
        "type": "vulnlab.task.state-changed.v1",
        "subject": f"tasks/{TASK_ID}",
        "time": "2026-07-10T16:00:00Z",
        "tenant_id": TENANT_ID,
        "project_id": PROJECT_ID,
        "trace_id": "1234567890abcdef1234567890abcdef",
        "correlation_id": None,
        "causation_id": None,
        "partition_key": TASK_ID,
        "data": {
            "task_id": TASK_ID,
            "task_version": 1,
            "from_state": "QUEUED",
            "to_state": "RUNNING",
            "occurred_by": USER_ID,
            "reason_code": None,
            "metadata": {"worker": "orchestrator-1"},
        },
    }


def valid_tool_definition() -> dict:
    return {
        "kind": "ToolDefinition",
        "metadata": {
            "id": "66666666-6666-4666-8666-666666666666",
            "name": "knowledge.lookup",
            "version": "1.0.0",
            "tenant_id": TENANT_ID,
            "project_id": PROJECT_ID,
        },
        "input_schema": {"type": "object"},
        "output_schema": {"type": "object"},
        "risk_level": "R0",
        "permissions": ["knowledge:read"],
        "timeout_seconds": 15,
    }


def test_all_signed_json_schemas_are_valid_draft_2020_12() -> None:
    result = check()
    assert result["valid"], result["errors"]
    assert set(result["schemas"]) == {
        "packages/api-contracts/events/task-event.v1.schema.json",
        "packages/api-contracts/protocol/domain-protocol.v1.schema.json",
    }


def test_task_event_contract_accepts_tenant_scoped_cloud_event() -> None:
    schema = load_schema(SCHEMA_PATHS[0])
    validate_instance(schema, valid_task_event())


@pytest.mark.parametrize(
    "mutation", ["missing_tenant", "extra_property", "bad_trace", "bad_subject"]
)
def test_task_event_contract_rejects_invalid_envelopes(mutation: str) -> None:
    schema = load_schema(SCHEMA_PATHS[0])
    value = deepcopy(valid_task_event())
    if mutation == "missing_tenant":
        value.pop("tenant_id")
    elif mutation == "extra_property":
        value["secret"] = "must-not-cross-contract"
    elif mutation == "bad_trace":
        value["trace_id"] = "short"
    else:
        value["subject"] = "other/44444444-4444-4444-8444-444444444444"
    with pytest.raises(SchemaValidationError):
        validate_instance(schema, value)


def test_domain_protocol_accepts_registered_tool_definition() -> None:
    schema = load_schema(SCHEMA_PATHS[1])
    validate_instance(schema, valid_tool_definition())


def test_domain_protocol_rejects_unregistered_kind_and_unknown_fields() -> None:
    schema = load_schema(SCHEMA_PATHS[1])
    unknown_kind = deepcopy(valid_tool_definition())
    unknown_kind["kind"] = "UnregisteredCapability"
    with pytest.raises(SchemaValidationError):
        validate_instance(schema, unknown_kind)
    extra_field = deepcopy(valid_tool_definition())
    extra_field["shell_command"] = "forbidden"
    with pytest.raises(SchemaValidationError):
        validate_instance(schema, extra_field)
