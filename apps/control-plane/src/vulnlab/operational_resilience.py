from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .config import Settings
from .repository import ControlPlaneRepository
from .validation_evidence_store import EvidenceStore

ACTIVE_EXECUTION_STATUSES = (
    "QUEUED",
    "PROVISIONING",
    "RUNNING",
    "COLLECTING_EVIDENCE",
    "VERIFYING",
)


class OperationalRateLimited(RuntimeError):
    pass


class OperationalQuotaExceeded(RuntimeError):
    pass


class OperationalQueueSaturated(RuntimeError):
    pass


class OperationalDependencyUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CapacityDecision:
    allowed: bool
    status_code: int
    code: Literal[
        "accepted",
        "rate_limited",
        "quota_exceeded",
        "dependency_unavailable",
        "queue_saturated",
    ]
    reason: str
    measurements: dict[str, Any]

    def raise_if_blocked(self) -> None:
        if self.allowed:
            return
        if self.code == "queue_saturated":
            raise OperationalQueueSaturated(self.reason)
        if self.code == "dependency_unavailable":
            raise OperationalDependencyUnavailable(self.reason)
        if self.code == "rate_limited":
            raise OperationalRateLimited(self.reason)
        raise OperationalQuotaExceeded(self.reason)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json(value: str | None, default: Any) -> Any:
    if value is None or value == "":
        return default
    return json.loads(value.lstrip("\ufeff"))


def _count(row: Any | None) -> int:
    if row is None:
        return 0
    return int(row["count"])


def _row_dict(row: Any) -> dict[str, Any]:
    keys = row.keys()
    return {key: row[key] for key in keys}


class OperationalResilienceService:
    """P12 HA/scaling/DR read model and guardrail service.

    This service intentionally keeps all authoritative state in the repository
    and object store adapters. It does not introduce process-local scheduling
    authority and does not execute chaos or recovery actions by default.
    """

    def __init__(
        self,
        db: ControlPlaneRepository,
        settings: Settings,
        evidence_store: EvidenceStore,
    ) -> None:
        self.db = db
        self.settings = settings
        self.evidence_store = evidence_store

    def register_service_instance(
        self,
        *,
        tenant_id: str,
        instance_id: str,
        kind: Literal["control_plane", "validation_worker", "api_gateway", "scheduler"],
        status: Literal["starting", "ready", "draining", "terminated"],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        metadata_json = json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True)
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO operational_service_instances(
                   id,tenant_id,kind,status,metadata_json,last_heartbeat_at,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,1)
                   ON CONFLICT(id) DO UPDATE SET
                       tenant_id=excluded.tenant_id,
                       kind=excluded.kind,
                       status=excluded.status,
                       metadata_json=excluded.metadata_json,
                       last_heartbeat_at=excluded.last_heartbeat_at,
                       updated_at=excluded.updated_at,
                       version=operational_service_instances.version+1""",
                (instance_id, tenant_id, kind, status, metadata_json, now, now, now),
            )
        return self.service_instances(kind=kind, limit=1)[0]

    def record_worker_heartbeat(
        self,
        *,
        tenant_id: str,
        worker_id: str,
        active_executions: int,
        sandbox_capacity: int,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        metadata_json = json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True)
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO operational_worker_heartbeats(
                   id,tenant_id,worker_id,active_executions,sandbox_capacity,metadata_json,
                   last_heartbeat_at,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,1)
                   ON CONFLICT(worker_id) DO UPDATE SET
                       tenant_id=excluded.tenant_id,
                       active_executions=excluded.active_executions,
                       sandbox_capacity=excluded.sandbox_capacity,
                       metadata_json=excluded.metadata_json,
                       last_heartbeat_at=excluded.last_heartbeat_at,
                       updated_at=excluded.updated_at,
                       version=operational_worker_heartbeats.version+1""",
                (
                    str(uuid.uuid4()),
                    tenant_id,
                    worker_id,
                    max(active_executions, 0),
                    max(sandbox_capacity, 0),
                    metadata_json,
                    now,
                    now,
                    now,
                ),
            )
        row = self.db.fetch_one(
            "SELECT * FROM operational_worker_heartbeats WHERE worker_id=?", (worker_id,)
        )
        if row is None:
            raise OperationalDependencyUnavailable("worker heartbeat was not persisted")
        return self._worker_row(row)

    def service_instances(
        self, *, kind: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if kind is None:
            rows = self.db.fetch_all(
                """SELECT * FROM operational_service_instances
                   ORDER BY updated_at DESC,id DESC LIMIT ?""",
                (min(max(limit, 1), 500),),
            )
        else:
            rows = self.db.fetch_all(
                """SELECT * FROM operational_service_instances
                   WHERE kind=? ORDER BY updated_at DESC,id DESC LIMIT ?""",
                (kind, min(max(limit, 1), 500)),
            )
        return [self._instance_row(row) for row in rows]

    def worker_heartbeats(self, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.fetch_all(
            """SELECT * FROM operational_worker_heartbeats
               ORDER BY last_heartbeat_at DESC,worker_id LIMIT ?""",
            (min(max(limit, 1), 500),),
        )
        return [self._worker_row(row) for row in rows]

    def queue_summary(self) -> dict[str, Any]:
        rows = self.db.fetch_all(
            """SELECT status,COUNT(*) AS count,COALESCE(MAX(attempt),0) AS max_attempt
               FROM validation_queue_messages GROUP BY status ORDER BY status"""
        )
        by_status = {
            str(row["status"]): {"count": int(row["count"]), "max_attempt": int(row["max_attempt"])}
            for row in rows
        }
        ready = int(by_status.get("ready", {}).get("count", 0))
        leased = int(by_status.get("leased", {}).get("count", 0))
        dead = int(by_status.get("dead", {}).get("count", 0))
        pending = ready + leased
        return {
            "by_status": by_status,
            "pending": pending,
            "ready": ready,
            "leased": leased,
            "dead_letter": dead,
            "saturated": pending >= self.settings.p12_queue_depth_threshold,
            "threshold": self.settings.p12_queue_depth_threshold,
        }

    def execution_load(self, *, tenant_id: str | None = None, project_id: str | None = None) -> int:
        placeholders = ",".join("?" for _ in ACTIVE_EXECUTION_STATUSES)
        params: list[Any] = list(ACTIVE_EXECUTION_STATUSES)
        sql = f"""SELECT COUNT(*) AS count FROM validation_executions ve
                  JOIN tasks t ON t.id=ve.task_id
                  WHERE ve.status IN ({placeholders})"""
        if tenant_id is not None:
            sql += " AND ve.tenant_id=?"
            params.append(tenant_id)
        if project_id is not None:
            sql += " AND COALESCE(t.workflow_name,'default')=?"
            params.append(project_id)
        return _count(self.db.fetch_one(sql, tuple(params)))

    def capacity_decision(self, *, tenant_id: str, project_id: str) -> CapacityDecision:
        queue = self.queue_summary()
        global_active = self.execution_load()
        tenant_active = self.execution_load(tenant_id=tenant_id)
        project_active = self.execution_load(tenant_id=tenant_id, project_id=project_id)
        measurements = {
            "queue_pending": queue["pending"],
            "queue_threshold": queue["threshold"],
            "global_active": global_active,
            "tenant_active": tenant_active,
            "project_active": project_active,
            "global_limit": self.settings.p12_global_concurrency_limit,
            "tenant_limit": self.settings.p12_tenant_concurrency_limit,
            "project_limit": self.settings.p12_project_concurrency_limit,
            "sandbox_capacity": self.settings.p12_sandbox_capacity_limit,
            "model_limit": self.settings.p12_model_concurrency_limit,
        }
        if queue["pending"] >= self.settings.p12_queue_depth_threshold:
            return CapacityDecision(
                False, 503, "queue_saturated", "validation queue saturated", measurements
            )
        if global_active >= self.settings.p12_max_pending_executions:
            return CapacityDecision(
                False, 503, "queue_saturated", "maximum pending executions reached", measurements
            )
        if global_active >= self.settings.p12_global_concurrency_limit:
            return CapacityDecision(
                False, 429, "quota_exceeded", "global concurrency quota exceeded", measurements
            )
        if tenant_active >= self.settings.p12_tenant_concurrency_limit:
            return CapacityDecision(
                False, 429, "quota_exceeded", "tenant concurrency quota exceeded", measurements
            )
        if project_active >= self.settings.p12_project_concurrency_limit:
            return CapacityDecision(
                False, 429, "quota_exceeded", "project concurrency quota exceeded", measurements
            )
        return CapacityDecision(True, 202, "accepted", "capacity available", measurements)

    def fairness_snapshot(self) -> dict[str, Any]:
        rows = self.db.fetch_all(
            """SELECT payload_json,status FROM validation_queue_messages
               WHERE status IN ('ready','leased')"""
        )
        tenants: dict[str, dict[str, int]] = {}
        for row in rows:
            payload = _json(row["payload_json"], {})
            tenant_id = str(payload.get("tenant_id", "unknown"))
            status = str(row["status"])
            tenants.setdefault(tenant_id, {"ready": 0, "leased": 0})
            tenants[tenant_id][status] += 1
        return {
            "policy": "weighted-fair-ready-queue-with-active-lease-pressure",
            "tenants": tenants,
            "priority_boundary": (
                "priority changes ordering only after scope, approval, policy, and quota checks"
            ),
        }

    def evidence_consistency_check(
        self,
        *,
        tenant_id: str,
        repair: bool = False,
        repair_action: Literal["none", "recompute_metadata_hash"] = "none",
    ) -> dict[str, Any]:
        if repair and repair_action == "none":
            raise ValueError("repair_action must be explicit when repair is true")
        rows = self.db.fetch_all(
            """SELECT * FROM validation_execution_evidence
               WHERE EXISTS (
                   SELECT 1 FROM validation_executions ve
                   WHERE ve.id=validation_execution_evidence.execution_id
                     AND ve.tenant_id=?
               )
               ORDER BY created_at,id""",
            (tenant_id,),
        )
        metadata_keys: set[str] = set()
        findings: list[dict[str, Any]] = []
        for row in rows:
            metadata = _json(row["metadata_json"], {})
            object_key = str(metadata.get("object_key", "")).strip()
            status = "healthy"
            details: dict[str, Any] = {
                "evidence_id": row["id"],
                "execution_id": row["execution_id"],
                "metadata_sha256": row["content_sha256"],
                "object_key": object_key,
            }
            if not object_key:
                status = "metadata_mismatch"
                details["reason"] = "metadata does not contain object_key"
            else:
                metadata_keys.add(object_key)
                inspected = self.evidence_store.inspect_json(object_key)
                details.update(
                    {
                        "object_exists": inspected.exists,
                        "object_sha256": inspected.content_sha256,
                        "object_size": inspected.size,
                        "backend": inspected.backend,
                    }
                )
                if not inspected.exists:
                    status = "missing_object"
                elif inspected.content_sha256 != row["content_sha256"]:
                    status = "hash_mismatch"
                    if repair and repair_action == "recompute_metadata_hash":
                        self.db.execute(
                            """UPDATE validation_execution_evidence
                               SET content_sha256=?,metadata_json=?
                               WHERE id=?""",
                            (
                                inspected.content_sha256,
                                json.dumps(
                                    {
                                        **metadata,
                                        "repaired_by": "p12_evidence_consistency_checker",
                                        "previous_content_sha256": row["content_sha256"],
                                    },
                                    ensure_ascii=False,
                                    sort_keys=True,
                                ),
                                row["id"],
                            ),
                        )
                        status = "healthy"
                        details["repair"] = "metadata_hash_recomputed"
                elif metadata.get("size") is not None and int(metadata["size"]) != inspected.size:
                    status = "metadata_mismatch"
            findings.append({"status": status, "details": details})

        prefix = f"tenant={tenant_id}/"
        try:
            inventory = self.evidence_store.list_json_objects(prefix=prefix)
        except Exception as exc:
            raise OperationalDependencyUnavailable("evidence object inventory failed") from exc
        for item in inventory:
            if item.object_key not in metadata_keys:
                findings.append(
                    {
                        "status": "orphan_object",
                        "details": {
                            "object_key": item.object_key,
                            "object_sha256": item.content_sha256,
                            "object_size": item.size,
                            "backend": item.backend,
                        },
                    }
                )

        summary = {
            "healthy": sum(1 for item in findings if item["status"] == "healthy"),
            "missing_object": sum(1 for item in findings if item["status"] == "missing_object"),
            "orphan_object": sum(1 for item in findings if item["status"] == "orphan_object"),
            "hash_mismatch": sum(1 for item in findings if item["status"] == "hash_mismatch"),
            "metadata_mismatch": sum(
                1 for item in findings if item["status"] == "metadata_mismatch"
            ),
        }
        overall = (
            "healthy"
            if all(value == 0 for key, value in summary.items() if key != "healthy")
            else "inconsistent"
        )
        report_id = str(uuid.uuid4())
        now = _now()
        self.db.execute(
            """INSERT INTO operational_evidence_consistency_reports(
               id,tenant_id,status,summary_json,findings_json,repair_action,created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,?,1)""",
            (
                report_id,
                tenant_id,
                overall,
                json.dumps(summary, ensure_ascii=False, sort_keys=True),
                json.dumps(findings, ensure_ascii=False, sort_keys=True),
                repair_action if repair else "none",
                now,
                now,
            ),
        )
        return {
            "id": report_id,
            "tenant_id": tenant_id,
            "status": overall,
            "summary": summary,
            "findings": findings,
            "repair_action": repair_action if repair else "none",
            "created_at": now,
        }

    def latest_evidence_report(self, *, tenant_id: str) -> dict[str, Any] | None:
        row = self.db.fetch_one(
            """SELECT * FROM operational_evidence_consistency_reports
               WHERE tenant_id=? ORDER BY created_at DESC,id DESC LIMIT 1""",
            (tenant_id,),
        )
        if row is None:
            return None
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "status": row["status"],
            "summary": _json(row["summary_json"], {}),
            "findings": _json(row["findings_json"], []),
            "repair_action": row["repair_action"],
            "created_at": row["created_at"],
        }

    def backup_status(self) -> dict[str, Any]:
        root = Path("infrastructure") / "backups"
        manifests = sorted(root.glob("*/manifest.json")) if root.is_dir() else []
        latest_manifest: dict[str, Any] | None = None
        if manifests:
            latest = manifests[-1]
            latest_manifest = {
                "path": str(latest).replace("\\", "/"),
                "content": _json(latest.read_text(encoding="utf-8"), {}),
            }
        return {
            "rpo_target_minutes": 15,
            "rto_target_minutes": 60,
            "latest_manifest": latest_manifest,
            "sla_claim": "target_only_until_runtime_drill_passes",
        }

    def disaster_recovery_plan(self) -> dict[str, Any]:
        return {
            "required_steps": [
                "create tenant/project/tasks/executions/evidence/cases/retests/evaluations",
                "backup PostgreSQL, MinIO, and required message state",
                "destroy isolated test data/environment",
                "redeploy infrastructure",
                "restore backups",
                "verify counts, relationships, evidence SHA-256, audit chain, and unfinished work",
                "rerun P9/P10/P11/P12 acceptance",
            ],
            "production_sla_claim": "not claimed by deterministic baseline",
        }

    def snapshot(self, *, tenant_id: str) -> dict[str, Any]:
        self.register_service_instance(
            tenant_id=tenant_id,
            instance_id=self.settings.control_plane_instance_id,
            kind="control_plane",
            status="ready",
            metadata={
                "repository_backend": self.settings.repository_backend,
                "queue_backend": self.settings.validation_queue_backend,
                "evidence_store_backend": self.settings.evidence_store_backend,
            },
        )
        queue = self.queue_summary()
        return {
            "version": "2.12.0-p12",
            "mode": {
                "environment": self.settings.env,
                "repository_backend": self.settings.repository_backend,
                "queue_backend": self.settings.validation_queue_backend,
                "sandbox_backend": self.settings.validation_sandbox_backend,
                "evidence_store_backend": self.settings.evidence_store_backend,
                "production_static_fallback_forbidden": self.settings.env
                not in {"production", "prod"}
                or (
                    self.settings.repository_backend == "postgres"
                    and self.settings.validation_queue_backend == "nats"
                    and self.settings.validation_sandbox_backend == "docker"
                    and self.settings.evidence_store_backend == "minio"
                ),
            },
            "service_instances": self.service_instances(limit=100),
            "workers": self.worker_heartbeats(limit=100),
            "queue": queue,
            "fairness": self.fairness_snapshot(),
            "capacity": {
                "global_concurrency_limit": self.settings.p12_global_concurrency_limit,
                "tenant_concurrency_limit": self.settings.p12_tenant_concurrency_limit,
                "project_concurrency_limit": self.settings.p12_project_concurrency_limit,
                "model_concurrency_limit": self.settings.p12_model_concurrency_limit,
                "sandbox_capacity_limit": self.settings.p12_sandbox_capacity_limit,
                "queue_depth_threshold": self.settings.p12_queue_depth_threshold,
                "max_pending_executions": self.settings.p12_max_pending_executions,
                "api_rate_limit_per_minute": self.settings.p12_api_rate_limit_per_minute,
                "database_pool_max_size": self.settings.database_pool_max_size,
                "minio_upload_concurrency_limit": self.settings.p12_minio_upload_concurrency_limit,
            },
            "database": {
                "pool_min_size": self.settings.database_pool_min_size,
                "pool_max_size": self.settings.database_pool_max_size,
                "pool_timeout_seconds": self.settings.database_pool_timeout_seconds,
                "retry_policy": {
                    "max_attempts": self.settings.p12_retry_max_attempts,
                    "base_delay_seconds": self.settings.p12_retry_base_delay_seconds,
                    "bounded": True,
                    "retryable_classes": [
                        "connection_interruption",
                        "deadlock",
                        "serialization_failure",
                    ],
                    "non_retryable_classes": [
                        "unique_violation",
                        "foreign_key_violation",
                        "policy_denied",
                    ],
                },
            },
            "nats": {
                "stream": self.settings.nats_stream,
                "subject": self.settings.nats_subject,
                "durable": self.settings.nats_durable,
                "dead_letter_status": "validation_queue_messages.status='dead'",
                "manual_replay": "reset dead/ready messages through controlled operator runbook only",
            },
            "evidence_consistency": self.latest_evidence_report(tenant_id=tenant_id),
            "backup": self.backup_status(),
            "disaster_recovery": self.disaster_recovery_plan(),
            "chaos": {
                "production_guard": "fault injection refuses production mode",
                "allowed_targets": [
                    "control_plane_instance",
                    "validation_worker",
                    "nats",
                    "postgres",
                    "minio",
                    "sandbox_timeout",
                    "model_timeout",
                    "duplicate_message",
                    "delayed_message",
                    "reordered_message",
                ],
            },
            "boundaries": [
                "no new validation templates",
                "no arbitrary PoC upload",
                "no arbitrary shell or command execution",
                "priority never bypasses scope, approval, policy, or quota",
                "evidence checker never deletes objects by default",
                "DR documents RPO/RTO as targets until runtime drill passes",
            ],
        }

    @staticmethod
    def _instance_row(row: Any) -> dict[str, Any]:
        data = _row_dict(row)
        data["metadata"] = _json(data.pop("metadata_json"), {})
        return data

    @staticmethod
    def _worker_row(row: Any) -> dict[str, Any]:
        data = _row_dict(row)
        data["metadata"] = _json(data.pop("metadata_json"), {})
        return data
