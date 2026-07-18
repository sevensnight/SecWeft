from __future__ import annotations

import hashlib
import hmac
import json
from contextlib import closing
from datetime import UTC, datetime
from typing import Any

from .repository import ControlPlaneRepository
from .security import redact


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


class AuditService:
    """Append-only, HMAC chained audit records."""

    def __init__(self, db: ControlPlaneRepository, key: bytes):
        self.db = db
        self.key = key

    def _digest(self, prev_hash: str, entry: dict[str, Any]) -> str:
        payload = (prev_hash + _canonical(entry)).encode()
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest()

    def record(
        self,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: str = "success",
        details: dict[str, Any] | None = None,
    ) -> int:
        timestamp = datetime.now(UTC).isoformat()
        safe_details = redact(details or {})
        details_json = _canonical(safe_details)
        with self.db.transaction() as connection:
            last = connection.execute(
                "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
            ).fetchone()
            head = connection.execute(
                "SELECT entry_count,last_hash FROM audit_head WHERE id=1"
            ).fetchone()
            if (last is None) != (head is None):
                raise RuntimeError("audit head/log mismatch; refusing to append")
            if last is not None and not hmac.compare_digest(last["entry_hash"], head["last_hash"]):
                raise RuntimeError("audit tail does not match signed head; refusing to append")
            prev_hash = head["last_hash"] if head else "0" * 64
            next_count = int(head["entry_count"]) + 1 if head else 1
            entry = {
                "timestamp": timestamp,
                "actor_id": actor_id,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "outcome": outcome,
                "details_json": details_json,
            }
            entry_hash = self._digest(prev_hash, entry)
            cursor = connection.execute(
                """INSERT INTO audit_logs(timestamp,actor_id,action,resource_type,resource_id,
                   outcome,details_json,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    timestamp,
                    actor_id,
                    action,
                    resource_type,
                    resource_id,
                    outcome,
                    details_json,
                    prev_hash,
                    entry_hash,
                ),
            )
            connection.execute(
                """INSERT INTO audit_head(id,entry_count,last_hash,updated_at) VALUES(1,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET entry_count=excluded.entry_count,
                   last_hash=excluded.last_hash,updated_at=excluded.updated_at""",
                (next_count, entry_hash, timestamp),
            )
            return int(cursor.lastrowid or 0)

    def verify(self) -> dict[str, int | bool | None]:
        # Read records and head from one SQLite snapshot so a concurrent append cannot
        # create a false integrity alarm between two separate connections.
        with closing(self.db.connect()) as connection:
            connection.execute("BEGIN")
            rows = list(connection.execute("SELECT * FROM audit_logs ORDER BY id").fetchall())
            head = connection.execute(
                "SELECT entry_count,last_hash FROM audit_head WHERE id=1"
            ).fetchone()
            connection.commit()
        prev_hash = "0" * 64
        for row in rows:
            entry = {
                "timestamp": row["timestamp"],
                "actor_id": row["actor_id"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "outcome": row["outcome"],
                "details_json": row["details_json"],
            }
            expected = self._digest(prev_hash, entry)
            if not hmac.compare_digest(row["prev_hash"], prev_hash) or not hmac.compare_digest(
                row["entry_hash"], expected
            ):
                return {"valid": False, "entries": len(rows), "first_invalid_id": int(row["id"])}
            prev_hash = row["entry_hash"]
        if head is None:
            if rows:
                return {
                    "valid": False,
                    "entries": len(rows),
                    "first_invalid_id": int(rows[-1]["id"]),
                }
        elif int(head["entry_count"]) != len(rows) or not hmac.compare_digest(
            head["last_hash"], prev_hash
        ):
            next_id = int(rows[-1]["id"]) + 1 if rows else 1
            return {"valid": False, "entries": len(rows), "first_invalid_id": next_id}
        return {"valid": True, "entries": len(rows), "first_invalid_id": None}

    def list(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        rows = self.db.fetch_all(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?",
            (min(max(limit, 1), 1000), max(offset, 0)),
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            result.append(item)
        return result
