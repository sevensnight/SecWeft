from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any


class JsonLogFormatter(logging.Formatter):
    """Small allow-list JSON formatter that cannot accidentally serialize request secrets."""

    _FIELDS = (
        "request_id",
        "trace_id",
        "method",
        "path",
        "status_code",
        "duration_ms",
        "tenant_id",
        "project_id",
        "user_id",
        "error_type",
    )

    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "service": "vulnlab-control-plane",
            "message": record.getMessage(),
        }
        for field in self._FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                event[field] = value
        return json.dumps(event, ensure_ascii=False, separators=(",", ":"))


def request_logger() -> logging.Logger:
    logger = logging.getLogger("vulnlab.request")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
