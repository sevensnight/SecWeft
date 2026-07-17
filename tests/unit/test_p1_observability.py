from __future__ import annotations

import json
import logging

from vulnlab.observability import JsonLogFormatter


def test_json_log_formatter_keeps_error_context_without_secret_fields() -> None:
    record = logging.LogRecord(
        name="vulnlab.request",
        level=logging.ERROR,
        pathname=__file__,
        lineno=12,
        msg="request.unexpected_error",
        args=(),
        exc_info=None,
    )
    record.request_id = "request-1"
    record.trace_id = "trace-1"
    record.path = "/api/v1/projects"
    record.error_type = "RuntimeError"
    record.authorization = "Bearer must-not-be-logged"
    record.request_body = {"token": "must-not-be-logged"}

    rendered = json.loads(JsonLogFormatter().format(record))

    assert rendered["error_type"] == "RuntimeError"
    assert rendered["request_id"] == "request-1"
    assert rendered["trace_id"] == "trace-1"
    assert "must-not-be-logged" not in json.dumps(rendered)
    assert "authorization" not in rendered
    assert "request_body" not in rendered
