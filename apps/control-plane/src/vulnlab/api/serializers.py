from __future__ import annotations

import json
from typing import Any


def serialize_scope(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "target_pattern": row["target_pattern"],
        "protocols": json.loads(row["protocols_json"]),
        "ports": json.loads(row["ports_json"]),
        "expires_at": row["expires_at"],
        "approved": bool(row["approved"]),
        "approved_by": row["approved_by"],
        "approved_at": row["approved_at"],
        "approval_reason": row["approval_reason"],
        "scope_hash": row["scope_hash"],
        "resolved_ips": json.loads(row["resolved_ips_json"]),
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }


def serialize_profile(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "target": row["target"],
        "proxy_url": row["proxy_url"],
        "proxy_scope_id": row["proxy_scope_id"],
        "intent": row["intent"],
        "indicators": json.loads(row["indicators_json"]),
        "scope_id": row["scope_id"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }
