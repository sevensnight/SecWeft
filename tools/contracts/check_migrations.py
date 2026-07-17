#!/usr/bin/env python3
"""Static safety and reversibility checks for ordered PostgreSQL migrations."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "infrastructure" / "migrations"
CREATE_TABLE = re.compile(
    r"CREATE\s+TABLE\s+([a-z_]+\.[a-z_]+)\s*\((.*?)\n\);", re.IGNORECASE | re.DOTALL
)
DROP_TABLE = re.compile(r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-z_]+\.[a-z_]+)\s*;", re.IGNORECASE)
MUTABLE_TABLES = frozenset(
    {
        "iam.tenants",
        "iam.projects",
        "iam.users",
        "iam.roles",
        "iam.permissions",
        "iam.role_permissions",
        "iam.user_roles",
        "control.tasks",
        "control.task_stages",
        "control.task_events",
        "control.outbox_events",
        "control.inbox_messages",
        "control.idempotency_records",
        "audit.events",
        "audit.chain_heads",
    }
)
TENANT_OWNED_TABLES = MUTABLE_TABLES - {"iam.tenants"}
REQUIRED_INDEXES = frozenset(
    {
        "idx_users_tenant_active",
        "idx_user_roles_user",
        "idx_tasks_project_status",
        "idx_tasks_requester",
        "idx_task_stages_ready",
        "idx_task_events_stream",
        "idx_outbox_unpublished",
        "idx_inbox_status",
        "idx_idempotency_expiry",
        "idx_audit_events_occurred",
        "idx_audit_events_trace",
        "idx_audit_events_request",
        "idx_audit_events_task",
        "idx_audit_events_actor",
    }
)


def migration_pairs() -> list[tuple[Path, Path]]:
    if not MIGRATIONS.is_dir():
        return []
    pairs: list[tuple[Path, Path]] = []
    for up in sorted(MIGRATIONS.glob("*.up.sql")):
        down = up.with_name(up.name.removesuffix(".up.sql") + ".down.sql")
        pairs.append((up, down))
    return pairs


def _normalized_tables(sql: str, pattern: re.Pattern[str]) -> set[str]:
    return {match.group(1).lower() for match in pattern.finditer(sql)}


def _ordered_tables(sql: str, pattern: re.Pattern[str]) -> list[str]:
    return [match.group(1).lower() for match in pattern.finditer(sql)]


def validate_pair(up_path: Path, down_path: Path, *, require_baseline: bool = False) -> list[str]:
    errors: list[str] = []
    if not down_path.is_file():
        return [f"down migration is missing for {up_path.name}"]
    up = up_path.read_text(encoding="utf-8")
    down = down_path.read_text(encoding="utf-8")
    lowered = (up + "\n" + down).lower()
    if any(marker in lowered for marker in ("todo", "fixme", "not implemented")):
        errors.append(f"placeholder marker found in {up_path.name}")
    if re.search(r"DROP\s+(?:TABLE|SCHEMA).*\bCASCADE\b", down, re.IGNORECASE):
        errors.append(f"destructive CASCADE is forbidden in {down_path.name}")
    for label, value in (("up", up), ("down", down)):
        if value.count("BEGIN;") != 1 or value.count("COMMIT;") != 1:
            errors.append(f"{label} migration must have exactly one explicit transaction")
        if value.count("(") != value.count(")"):
            errors.append(f"unbalanced parentheses in {label} migration")

    created = _normalized_tables(up, CREATE_TABLE)
    dropped = _normalized_tables(down, DROP_TABLE)
    if created != dropped:
        missing_down = sorted(created - dropped)
        extra_down = sorted(dropped - created)
        if missing_down:
            errors.append(f"tables missing from down migration: {', '.join(missing_down)}")
        if extra_down:
            errors.append(f"down migration drops tables not created by up: {', '.join(extra_down)}")
    created_order = _ordered_tables(up, CREATE_TABLE)
    dropped_order = _ordered_tables(down, DROP_TABLE)
    if dropped_order != list(reversed(created_order)):
        errors.append("down migration must drop tables in exact reverse dependency order")
    bodies = {match.group(1).lower(): match.group(2).lower() for match in CREATE_TABLE.finditer(up)}
    for table in sorted(created):
        body = bodies[table]
        for column in ("created_at", "updated_at", "version"):
            if not re.search(rf"\b{column}\b", body):
                errors.append(f"{table} lacks required {column}")
        if table != "iam.tenants" and not re.search(r"\btenant_id\s+uuid\s+not\s+null\b", body):
            errors.append(f"{table} lacks a non-null tenant_id")

    if require_baseline:
        missing_tables = sorted(MUTABLE_TABLES - created)
        if missing_tables:
            errors.append(f"required P0 tables are missing: {', '.join(missing_tables)}")
        for schema in ("iam", "control", "audit"):
            if not re.search(
                rf"CREATE\s+SCHEMA\s+IF\s+NOT\s+EXISTS\s+{schema}\s*;", up, re.IGNORECASE
            ):
                errors.append(f"schema {schema} is not created")
            if not re.search(rf"DROP\s+SCHEMA\s+IF\s+EXISTS\s+{schema}\s*;", down, re.IGNORECASE):
                errors.append(f"schema {schema} is not removed by rollback")
        dropped_schemas = [
            match.group(1).lower()
            for match in re.finditer(
                r"DROP\s+SCHEMA\s+IF\s+EXISTS\s+([a-z_]+)\s*;", down, re.IGNORECASE
            )
        ]
        if dropped_schemas != ["audit", "control", "iam"]:
            errors.append(
                "down migration must remove audit, control, and iam schemas in reverse order"
            )

        indexes = {
            match.group(1).lower()
            for match in re.finditer(
                r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+([a-z0-9_]+)", up, re.IGNORECASE
            )
        }
        missing_indexes = sorted(REQUIRED_INDEXES - indexes)
        if missing_indexes:
            errors.append(f"required indexes are missing: {', '.join(missing_indexes)}")

        required_fragments = {
            "tenant-safe project FK": "FOREIGN KEY (tenant_id, project_id)",
            "optimistic task update version": "CONSTRAINT ck_tasks_version CHECK (version > 0)",
            "transactional outbox": "CREATE TABLE control.outbox_events",
            "outbox event deduplication": (
                "CONSTRAINT uq_outbox_events_event UNIQUE (tenant_id, event_id)"
            ),
            "idempotent inbox": "uq_inbox_consumer_message",
            "HTTP idempotency": "CREATE TABLE control.idempotency_records",
            "tenant HTTP idempotency uniqueness": (
                "ON control.idempotency_records (tenant_id, operation, idempotency_key)"
            ),
            "project HTTP idempotency uniqueness": (
                "ON control.idempotency_records (tenant_id, project_id, operation, idempotency_key)"
            ),
            "append-only audit trigger": "CREATE TRIGGER trg_audit_events_append_only",
            "audit mutation rejection": "CREATE FUNCTION audit.reject_event_mutation()",
            "audit trace identifier": "trace_id varchar(64) NOT NULL",
            "audit request identifier": "request_id varchar(64) NOT NULL",
        }
        for label, fragment in required_fragments.items():
            if fragment.lower() not in up.lower():
                errors.append(f"missing invariant: {label}")

    tenant_unsafe_references = sorted(
        {
            match.group(0)
            for match in re.finditer(
                r"REFERENCES\s+(?:iam\.(?:projects|users|roles|permissions)|control\.tasks)\s*\(\s*id\s*\)",
                up,
                re.IGNORECASE,
            )
        }
    )
    if tenant_unsafe_references:
        errors.append(
            "tenant-owned foreign keys must include tenant_id; unsafe references: "
            + ", ".join(tenant_unsafe_references)
        )
    return errors


def check() -> dict[str, Any]:
    pairs = migration_pairs()
    errors: list[str] = []
    if not pairs:
        errors.append("no reversible *.up.sql/*.down.sql migration pair exists")
    for index, (up, down) in enumerate(pairs):
        errors.extend(
            f"{up.name}: {error}" for error in validate_pair(up, down, require_baseline=index == 0)
        )
    return {
        "valid": not errors,
        "migration_directory": str(MIGRATIONS.relative_to(ROOT)).replace("\\", "/"),
        "pairs": [up.name.removesuffix(".up.sql") for up, _ in pairs],
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate ordered PostgreSQL migrations without mutating a database"
    )
    parser.parse_args()
    result = check()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
