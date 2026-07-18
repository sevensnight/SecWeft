from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from .audit import AuditService
from .policy import PolicyService
from .repository import ControlPlaneRepository
from .schemas import (
    EnvironmentPromotionCreate,
    LicenseScanResultCreate,
    PolicyEvaluationRequest,
    ProvenanceStatementCreate,
    ReleaseApprovalCreate,
    ReleaseArtifactCreate,
    ReleaseCandidateCreate,
    ReleaseExceptionCreate,
    ReleaseGateEvaluationRequest,
    RollbackCreate,
    SBOMDocumentCreate,
    SecurityScanResultCreate,
    SignatureRecordCreate,
)
from .security import Principal


class ReleaseGovernanceError(ValueError):
    pass


class ReleaseIsolationError(ReleaseGovernanceError):
    pass


class ReleaseStateError(ReleaseGovernanceError):
    pass


ENVIRONMENT_ORDER = ("development", "integration", "staging", "production")
RELEASE_GATES = (
    "source_tree_clean",
    "source_commit_exists",
    "p0_p12_baseline",
    "p11_evaluation_gates",
    "p12_authoritative_runtime",
    "unit_integration_e2e",
    "openapi_snapshot",
    "migration_compatibility",
    "sbom_generated",
    "license_policy",
    "vulnerability_policy",
    "secret_scan",
    "container_scan",
    "signature_valid",
    "provenance_valid",
    "helm_lint",
    "helm_policy",
    "configuration_policy",
    "backup_readiness",
    "rollback_readiness",
)
DRIFT_FIELDS = {
    "IMAGE_DRIFT": "image_digest",
    "CONFIG_DRIFT": "configuration_hash",
    "REPLICA_DRIFT": "replicas",
    "RESOURCE_LIMIT_DRIFT": "resource_limits",
    "SECURITY_CONTEXT_DRIFT": "security_context",
    "SECRET_REFERENCE_DRIFT": "secret_refs",
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _future(hours: int) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).isoformat()


def _json(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
        ).encode()
    ).hexdigest()


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes"}
    return bool(value)


class ReleaseGovernanceService:
    def __init__(self, db: ControlPlaneRepository, policy: PolicyService, audit: AuditService):
        self.db = db
        self.policy = policy
        self.audit = audit

    def _tenant_id(self, principal: Principal, requested: str) -> str:
        if principal.role.value == "admin":
            return requested
        return principal.id

    def _visible_clause(self, principal: Principal) -> tuple[str, tuple[Any, ...]]:
        if principal.role.value == "admin":
            return "", ()
        return "tenant_id=?", (principal.id,)

    def _enforce_policy(
        self,
        principal: Principal,
        action: str,
        resource_type: str,
        resource_id: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.policy.enforce(
            principal,
            PolicyEvaluationRequest(
                action=cast(Any, action),
                resource_type=resource_type,
                resource_id=resource_id,
                metadata=metadata or {},
            ),
        )

    def _audit(
        self,
        principal: Principal,
        action: str,
        resource_type: str,
        resource_id: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.audit.record(
            principal.id,
            action,
            resource_type,
            resource_id,
            "success",
            details or {},
        )

    def _idempotent_response(
        self,
        principal: Principal,
        operation: str,
        idempotency_key: str | None,
        request_hash: str,
    ) -> dict[str, Any] | None:
        if not idempotency_key or len(idempotency_key) > 200:
            raise ReleaseStateError(
                "Idempotency-Key is required and must be at most 200 characters"
            )
        row = self.db.fetch_one(
            """SELECT * FROM task_idempotency_records
               WHERE principal_id=? AND operation=? AND idempotency_key=?""",
            (principal.id, operation, idempotency_key),
        )
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise ReleaseStateError("Idempotency-Key was reused with a different release request")
        if row["response_json"]:
            return _json(row["response_json"], {})
        raise ReleaseStateError("idempotent release request is still processing")

    def _store_idempotency(
        self,
        principal: Principal,
        operation: str,
        idempotency_key: str,
        request_hash: str,
        response: dict[str, Any],
        *,
        resource_type: str,
        resource_id: str,
    ) -> None:
        now = _now()
        self.db.execute(
            """INSERT INTO task_idempotency_records(
               id,principal_id,operation,idempotency_key,request_hash,response_json,
               resource_type,resource_id,status,expires_at,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                principal.id,
                operation,
                idempotency_key,
                request_hash,
                _json_dumps(response),
                resource_type,
                resource_id,
                "completed",
                _future(24),
                now,
                now,
            ),
        )

    def _require_visible(self, principal: Principal, table: str, resource_id: str) -> Any:
        row = self.db.fetch_one(f"SELECT * FROM {table} WHERE id=?", (resource_id,))
        if row is None:
            raise KeyError(f"{table} not found")
        if principal.role.value != "admin" and row["tenant_id"] != principal.id:
            raise KeyError(f"{table} not found")
        return row

    @staticmethod
    def _artifact_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "name": row["name"],
            "artifact_type": row["artifact_type"],
            "digest": row["digest"],
            "repository": row["repository"],
            "source_commit": row["source_commit"],
            "metadata": _json(row["metadata_json"], {}),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _sbom_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "artifact_id": row["artifact_id"],
            "format": row["format"],
            "generator": row["generator"],
            "generated_at": row["generated_at"],
            "artifact_digest": row["artifact_digest"],
            "document_digest": row["document_digest"],
            "component_count": int(row["component_count"]),
            "license_summary": _json(row["license_summary_json"], {}),
            "vulnerability_summary": _json(row["vulnerability_summary_json"], {}),
            "document_ref": row["document_ref"],
            "created_at": row["created_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _provenance_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "artifact_id": row["artifact_id"],
            "subject_digest": row["subject_digest"],
            "source_repository": row["source_repository"],
            "source_commit": row["source_commit"],
            "builder_workflow": row["builder_workflow"],
            "statement_digest": row["statement_digest"],
            "predicate_type": row["predicate_type"],
            "verified": _bool(row["verified"]),
            "metadata": _json(row["metadata_json"], {}),
            "created_at": row["created_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _signature_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "artifact_id": row["artifact_id"],
            "signature_digest": row["signature_digest"],
            "signature_identity": row["signature_identity"],
            "certificate_issuer": row["certificate_issuer"],
            "verified": _bool(row["verified"]),
            "verification_error": row["verification_error"],
            "created_at": row["created_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _security_scan_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "artifact_id": row["artifact_id"],
            "scanner": row["scanner"],
            "severity_summary": _json(row["severity_summary_json"], {}),
            "critical_count": int(row["critical_count"]),
            "high_count": int(row["high_count"]),
            "unresolved_critical": _bool(row["unresolved_critical"]),
            "scan_digest": row["scan_digest"],
            "created_at": row["created_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _license_scan_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "artifact_id": row["artifact_id"],
            "scanner": row["scanner"],
            "license_summary": _json(row["license_summary_json"], {}),
            "prohibited_licenses": _json(row["prohibited_licenses_json"], []),
            "passed": _bool(row["passed"]),
            "scan_digest": row["scan_digest"],
            "created_at": row["created_at"],
            "version": int(row["version"]),
        }

    def _candidate_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "name": row["name"],
            "artifact_id": row["artifact_id"],
            "source_commit": row["source_commit"],
            "image_digest": row["image_digest"],
            "sbom_digest": row["sbom_digest"],
            "provenance_digest": row["provenance_digest"],
            "signature_digest": row["signature_digest"],
            "configuration_hash": row["configuration_hash"],
            "migration_set": _json(row["migration_set_json"], []),
            "helm_chart_digest": row["helm_chart_digest"],
            "status": row["status"],
            "freeze_hash": row["freeze_hash"],
            "metadata": _json(row["metadata_json"], {}),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _gate_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "candidate_id": row["candidate_id"],
            "gate_id": row["gate_id"],
            "environment": row["environment"],
            "status": row["status"],
            "reason": row["reason"],
            "evidence": _json(row["evidence_json"], {}),
            "evaluated_by": row["evaluated_by"],
            "policy_decision_id": row["policy_decision_id"],
            "created_at": row["created_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _approval_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "candidate_id": row["candidate_id"],
            "environment": row["environment"],
            "decision": row["decision"],
            "reason": row["reason"],
            "approved_by": row["approved_by"],
            "created_at": row["created_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _exception_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "candidate_id": row["candidate_id"],
            "gate_id": row["gate_id"],
            "reason": row["reason"],
            "risk": row["risk"],
            "scope": row["scope"],
            "requested_by": row["requested_by"],
            "approved_by": row["approved_by"],
            "expires_at": row["expires_at"],
            "compensating_controls": _json(row["compensating_controls_json"], []),
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _promotion_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "candidate_id": row["candidate_id"],
            "environment": row["environment"],
            "status": row["status"],
            "promoted_by": row["promoted_by"],
            "policy_decision_id": row["policy_decision_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _deployment_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "promotion_id": row["promotion_id"],
            "candidate_id": row["candidate_id"],
            "environment": row["environment"],
            "image_digest": row["image_digest"],
            "canary_percentage": int(row["canary_percentage"]),
            "status": row["status"],
            "health": _json(row["health_json"], {}),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _rollback_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "deployment_id": row["deployment_id"],
            "candidate_id": row["candidate_id"],
            "environment": row["environment"],
            "reason": row["reason"],
            "requested_by": row["requested_by"],
            "approved_by": row["approved_by"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _drift_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "deployment_id": row["deployment_id"],
            "status": row["status"],
            "drift_types": _json(row["drift_types_json"], []),
            "expected": _json(row["expected_json"], {}),
            "actual": _json(row["actual_json"], {}),
            "reviewed_by": row["reviewed_by"],
            "created_at": row["created_at"],
            "version": int(row["version"]),
        }

    @staticmethod
    def _compliance_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "candidate_id": row["candidate_id"],
            "package_digest": row["package_digest"],
            "contents": _json(row["contents_json"], {}),
            "generated_by": row["generated_by"],
            "created_at": row["created_at"],
            "version": int(row["version"]),
        }

    def _artifact_detail(self, row: Any) -> dict[str, Any]:
        artifact = self._artifact_row(row)
        artifact_id = artifact["id"]
        artifact["sbom_documents"] = [
            self._sbom_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_sbom_documents WHERE artifact_id=? ORDER BY created_at DESC",
                (artifact_id,),
            )
        ]
        artifact["provenance_statements"] = [
            self._provenance_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_provenance_statements WHERE artifact_id=? ORDER BY created_at DESC",
                (artifact_id,),
            )
        ]
        artifact["signature_records"] = [
            self._signature_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_signature_records WHERE artifact_id=? ORDER BY created_at DESC",
                (artifact_id,),
            )
        ]
        artifact["security_scans"] = [
            self._security_scan_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_security_scan_results WHERE artifact_id=? ORDER BY created_at DESC",
                (artifact_id,),
            )
        ]
        artifact["license_scans"] = [
            self._license_scan_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_license_scan_results WHERE artifact_id=? ORDER BY created_at DESC",
                (artifact_id,),
            )
        ]
        return artifact

    def register_artifact(
        self,
        principal: Principal,
        value: ReleaseArtifactCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest(value.model_dump(mode="json"))
        replay = self._idempotent_response(
            principal, "release.artifact.register", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        self._enforce_policy(
            principal,
            "release.artifact.register",
            "release_artifact",
            value.digest,
            metadata={"artifact_type": value.artifact_type},
        )
        existing = self.db.fetch_one(
            "SELECT * FROM release_artifacts WHERE tenant_id=? AND digest=?",
            (self._tenant_id(principal, value.tenant_id), value.digest),
        )
        if existing is not None:
            response = self._artifact_detail(existing)
            self._store_idempotency(
                principal,
                "release.artifact.register",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="release_artifact",
                resource_id=response["id"],
            )
            return response
        now = _now()
        artifact_id = str(uuid.uuid4())
        tenant_id = self._tenant_id(principal, value.tenant_id)
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO release_artifacts(
                   id,tenant_id,project_id,name,artifact_type,digest,repository,source_commit,
                   metadata_json,created_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    artifact_id,
                    tenant_id,
                    value.project_id,
                    value.name,
                    value.artifact_type,
                    value.digest,
                    value.repository,
                    value.source_commit,
                    _json_dumps(value.metadata),
                    principal.id,
                    now,
                    now,
                ),
            )
            if value.sbom is not None:
                self._insert_sbom(connection, artifact_id, value.sbom, now)
            if value.provenance is not None:
                self._insert_provenance(connection, artifact_id, value.provenance, now)
            if value.signature is not None:
                self._insert_signature(connection, artifact_id, value.signature, now)
            if value.security_scan is not None:
                self._insert_security_scan(connection, artifact_id, value.security_scan, now)
            if value.license_scan is not None:
                self._insert_license_scan(connection, artifact_id, value.license_scan, now)
        row = self._require_visible(principal, "release_artifacts", artifact_id)
        response = self._artifact_detail(row)
        self._store_idempotency(
            principal,
            "release.artifact.register",
            idempotency_key or "",
            request_hash,
            response,
            resource_type="release_artifact",
            resource_id=artifact_id,
        )
        self._audit(
            principal,
            "release.artifact.register",
            "release_artifact",
            artifact_id,
            details={"digest": value.digest, "artifact_type": value.artifact_type},
        )
        return response

    @staticmethod
    def _insert_sbom(
        connection: Any, artifact_id: str, value: SBOMDocumentCreate, now: str
    ) -> None:
        connection.execute(
            """INSERT INTO release_sbom_documents(
               id,artifact_id,format,generator,generated_at,artifact_digest,document_digest,
               component_count,license_summary_json,vulnerability_summary_json,document_ref,
               created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
            (
                str(uuid.uuid4()),
                artifact_id,
                value.format,
                value.generator,
                value.generated_at.isoformat(),
                value.artifact_digest,
                value.document_digest,
                value.component_count,
                _json_dumps(value.license_summary),
                _json_dumps(value.vulnerability_summary),
                value.document_ref,
                now,
                now,
            ),
        )

    @staticmethod
    def _insert_provenance(
        connection: Any, artifact_id: str, value: ProvenanceStatementCreate, now: str
    ) -> None:
        connection.execute(
            """INSERT INTO release_provenance_statements(
               id,artifact_id,subject_digest,source_repository,source_commit,builder_workflow,
               statement_digest,predicate_type,verified,metadata_json,created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)""",
            (
                str(uuid.uuid4()),
                artifact_id,
                value.subject_digest,
                value.source_repository,
                value.source_commit,
                value.builder_workflow,
                value.statement_digest,
                value.predicate_type,
                int(value.verified),
                _json_dumps(value.metadata),
                now,
                now,
            ),
        )

    @staticmethod
    def _insert_signature(
        connection: Any, artifact_id: str, value: SignatureRecordCreate, now: str
    ) -> None:
        connection.execute(
            """INSERT INTO release_signature_records(
               id,artifact_id,signature_digest,signature_identity,certificate_issuer,verified,
               verification_error,created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,?,?,1)""",
            (
                str(uuid.uuid4()),
                artifact_id,
                value.signature_digest,
                value.signature_identity,
                value.certificate_issuer,
                int(value.verified),
                value.verification_error,
                now,
                now,
            ),
        )

    @staticmethod
    def _insert_security_scan(
        connection: Any, artifact_id: str, value: SecurityScanResultCreate, now: str
    ) -> None:
        connection.execute(
            """INSERT INTO release_security_scan_results(
               id,artifact_id,scanner,severity_summary_json,critical_count,high_count,
               unresolved_critical,scan_digest,created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,?,?,?,1)""",
            (
                str(uuid.uuid4()),
                artifact_id,
                value.scanner,
                _json_dumps(value.severity_summary),
                value.critical_count,
                value.high_count,
                int(value.unresolved_critical),
                value.scan_digest,
                now,
                now,
            ),
        )

    @staticmethod
    def _insert_license_scan(
        connection: Any, artifact_id: str, value: LicenseScanResultCreate, now: str
    ) -> None:
        connection.execute(
            """INSERT INTO release_license_scan_results(
               id,artifact_id,scanner,license_summary_json,prohibited_licenses_json,passed,
               scan_digest,created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,?,?,1)""",
            (
                str(uuid.uuid4()),
                artifact_id,
                value.scanner,
                _json_dumps(value.license_summary),
                _json_dumps(value.prohibited_licenses),
                int(value.passed),
                value.scan_digest,
                now,
                now,
            ),
        )

    def list_artifacts(
        self, principal: Principal, *, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        clause, params = self._visible_clause(principal)
        where = f"WHERE {clause}" if clause else ""
        rows = self.db.fetch_all(
            f"SELECT * FROM release_artifacts {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, min(max(limit, 1), 500), max(offset, 0)),
        )
        return [self._artifact_row(row) for row in rows]

    def get_artifact(self, principal: Principal, artifact_id: str) -> dict[str, Any]:
        row = self._require_visible(principal, "release_artifacts", artifact_id)
        return self._artifact_detail(row)

    def _artifact_components(self, artifact_id: str) -> dict[str, Any]:
        sbom = self.db.fetch_one(
            "SELECT * FROM release_sbom_documents WHERE artifact_id=? ORDER BY created_at DESC LIMIT 1",
            (artifact_id,),
        )
        provenance = self.db.fetch_one(
            "SELECT * FROM release_provenance_statements WHERE artifact_id=? ORDER BY created_at DESC LIMIT 1",
            (artifact_id,),
        )
        signature = self.db.fetch_one(
            "SELECT * FROM release_signature_records WHERE artifact_id=? ORDER BY created_at DESC LIMIT 1",
            (artifact_id,),
        )
        security_scan = self.db.fetch_one(
            "SELECT * FROM release_security_scan_results WHERE artifact_id=? ORDER BY created_at DESC LIMIT 1",
            (artifact_id,),
        )
        license_scan = self.db.fetch_one(
            "SELECT * FROM release_license_scan_results WHERE artifact_id=? ORDER BY created_at DESC LIMIT 1",
            (artifact_id,),
        )
        return {
            "sbom": sbom,
            "provenance": provenance,
            "signature": signature,
            "security_scan": security_scan,
            "license_scan": license_scan,
        }

    def create_candidate(
        self,
        principal: Principal,
        value: ReleaseCandidateCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest(value.model_dump(mode="json"))
        replay = self._idempotent_response(
            principal, "release.candidate.create", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        artifact = self._require_visible(principal, "release_artifacts", value.artifact_id)
        tenant_id = self._tenant_id(principal, value.tenant_id)
        if artifact["tenant_id"] != tenant_id or artifact["project_id"] != value.project_id:
            raise ReleaseIsolationError("artifact belongs to another tenant or project")
        components = self._artifact_components(value.artifact_id)
        missing = [name for name, row in components.items() if row is None]
        if missing:
            raise ReleaseStateError(
                f"release candidate cannot be frozen; missing {', '.join(missing)}"
            )
        if not _bool(components["signature"]["verified"]):
            raise ReleaseStateError("release candidate requires a verified signature record")
        if not _bool(components["provenance"]["verified"]):
            raise ReleaseStateError("release candidate requires a verified provenance statement")
        self._enforce_policy(
            principal,
            "release.candidate.create",
            "release_candidate",
            value.name,
            metadata={"artifact_id": value.artifact_id},
        )
        candidate_id = str(uuid.uuid4())
        now = _now()
        freeze_payload = {
            "source_commit": artifact["source_commit"],
            "image_digest": artifact["digest"],
            "sbom_digest": components["sbom"]["document_digest"],
            "provenance_digest": components["provenance"]["statement_digest"],
            "signature_digest": components["signature"]["signature_digest"],
            "configuration_hash": value.configuration_hash,
            "migration_set": value.migration_set,
            "helm_chart_digest": value.helm_chart_digest,
        }
        freeze_hash = _digest(freeze_payload)
        self.db.execute(
            """INSERT INTO release_candidates(
               id,tenant_id,project_id,name,artifact_id,source_commit,image_digest,sbom_digest,
               provenance_digest,signature_digest,configuration_hash,migration_set_json,
               helm_chart_digest,status,freeze_hash,metadata_json,created_by,created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
            (
                candidate_id,
                tenant_id,
                value.project_id,
                value.name,
                value.artifact_id,
                artifact["source_commit"],
                artifact["digest"],
                components["sbom"]["document_digest"],
                components["provenance"]["statement_digest"],
                components["signature"]["signature_digest"],
                value.configuration_hash,
                _json_dumps(value.migration_set),
                value.helm_chart_digest,
                "frozen",
                freeze_hash,
                _json_dumps(value.metadata),
                principal.id,
                now,
                now,
            ),
        )
        response = self.get_candidate(principal, candidate_id)
        self._store_idempotency(
            principal,
            "release.candidate.create",
            idempotency_key or "",
            request_hash,
            response,
            resource_type="release_candidate",
            resource_id=candidate_id,
        )
        self._audit(
            principal,
            "release.candidate.create",
            "release_candidate",
            candidate_id,
            details=freeze_payload,
        )
        return response

    def list_candidates(
        self, principal: Principal, *, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        clause, params = self._visible_clause(principal)
        where = f"WHERE {clause}" if clause else ""
        rows = self.db.fetch_all(
            f"SELECT * FROM release_candidates {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            (*params, min(max(limit, 1), 500), max(offset, 0)),
        )
        return [self._candidate_row(row) for row in rows]

    def get_candidate(self, principal: Principal, candidate_id: str) -> dict[str, Any]:
        row = self._require_visible(principal, "release_candidates", candidate_id)
        candidate = self._candidate_row(row)
        artifact = self._require_visible(principal, "release_artifacts", candidate["artifact_id"])
        candidate["artifact"] = self._artifact_detail(artifact)
        candidate["gates"] = [
            self._gate_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_gate_results WHERE candidate_id=? ORDER BY created_at DESC",
                (candidate_id,),
            )
        ]
        candidate["approvals"] = [
            self._approval_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_approvals WHERE candidate_id=? ORDER BY created_at DESC",
                (candidate_id,),
            )
        ]
        candidate["exceptions"] = [
            self._exception_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_exceptions WHERE candidate_id=? ORDER BY created_at DESC",
                (candidate_id,),
            )
        ]
        candidate["promotions"] = [
            self._promotion_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_environment_promotions WHERE candidate_id=? ORDER BY created_at DESC",
                (candidate_id,),
            )
        ]
        candidate["deployments"] = [
            self._deployment_row(item)
            for item in self.db.fetch_all(
                "SELECT * FROM release_deployment_records WHERE candidate_id=? ORDER BY created_at DESC",
                (candidate_id,),
            )
        ]
        return candidate

    def _gate_statuses(self, candidate: Any, environment: str) -> list[dict[str, Any]]:
        artifact = self.db.fetch_one(
            "SELECT * FROM release_artifacts WHERE id=?", (candidate["artifact_id"],)
        )
        if artifact is None:
            raise ReleaseStateError("candidate artifact is missing")
        components = self._artifact_components(candidate["artifact_id"])
        metadata = _json(candidate["metadata_json"], {})
        accepted_runtime = (
            metadata.get("p12_authoritative_runtime", {}).get("status") == "RUNTIME_ACCEPTED"
            and metadata.get("p12_authoritative_runtime", {}).get("runtime") is True
            and metadata.get("p12_authoritative_runtime", {}).get("runtime_not_claimed") is False
        )
        license_passed = components["license_scan"] is not None and _bool(
            components["license_scan"]["passed"]
        )
        unresolved_critical = components["security_scan"] is None or _bool(
            components["security_scan"]["unresolved_critical"]
        )
        static_defaults = {
            "source_tree_clean": metadata.get("source_tree_clean", True),
            "source_commit_exists": bool(candidate["source_commit"]),
            "p0_p12_baseline": metadata.get("p0_p12_baseline", True),
            "p11_evaluation_gates": metadata.get("p11_evaluation_gates", True),
            "unit_integration_e2e": metadata.get("unit_integration_e2e", True),
            "openapi_snapshot": metadata.get("openapi_snapshot", True),
            "migration_compatibility": metadata.get("migration_compatibility", True),
            "secret_scan": metadata.get("secret_scan", True),
            "container_scan": metadata.get("container_scan", True),
            "helm_lint": metadata.get("helm_lint", True),
            "helm_policy": metadata.get("helm_policy", True),
            "configuration_policy": metadata.get("configuration_policy", True),
            "backup_readiness": metadata.get("backup_readiness", True),
            "rollback_readiness": metadata.get("rollback_readiness", True),
        }
        result: list[dict[str, Any]] = []
        for gate_id in RELEASE_GATES:
            status = "passed"
            reason = "gate passed"
            evidence: dict[str, Any] = {"environment": environment}
            if gate_id in static_defaults and not static_defaults[gate_id]:
                status = "failed"
                reason = f"{gate_id} evidence is missing or failed"
            elif gate_id == "sbom_generated":
                status = "passed" if components["sbom"] is not None else "failed"
                reason = "SBOM document is present" if status == "passed" else "SBOM is missing"
            elif gate_id == "license_policy":
                status = "passed" if license_passed else "failed"
                reason = (
                    "license scan passed"
                    if status == "passed"
                    else "license scan missing or failed"
                )
            elif gate_id == "vulnerability_policy":
                status = "failed" if unresolved_critical else "passed"
                reason = (
                    "unresolved critical vulnerabilities are present"
                    if status == "failed"
                    else "no unresolved critical vulnerabilities"
                )
            elif gate_id == "signature_valid":
                status = "passed" if _bool(components["signature"]["verified"]) else "failed"
                reason = "signature verified" if status == "passed" else "signature is not verified"
            elif gate_id == "provenance_valid":
                provenance = components["provenance"]
                valid_subject = provenance["subject_digest"] == artifact["digest"]
                valid_commit = provenance["source_commit"] == artifact["source_commit"]
                status = (
                    "passed"
                    if _bool(provenance["verified"]) and valid_subject and valid_commit
                    else "failed"
                )
                reason = (
                    "provenance subject and source commit verified"
                    if status == "passed"
                    else "provenance subject or source commit mismatch"
                )
            elif gate_id == "p12_authoritative_runtime":
                if accepted_runtime:
                    status = "passed"
                    reason = "P12 authoritative runtime accepted"
                elif environment == "production":
                    status = "failed"
                    reason = "production requires P12 authoritative runtime acceptance"
                else:
                    status = "warning"
                    reason = "P12 authoritative runtime not claimed; non-production policy warning"
            evidence["candidate_id"] = candidate["id"]
            result.append(
                {"gate_id": gate_id, "status": status, "reason": reason, "evidence": evidence}
            )
        return result

    def evaluate_candidate(
        self,
        principal: Principal,
        candidate_id: str,
        value: ReleaseGateEvaluationRequest,
        *,
        idempotency_key: str | None,
    ) -> list[dict[str, Any]]:
        request_hash = _digest({"candidate_id": candidate_id, **value.model_dump(mode="json")})
        replay = self._idempotent_response(
            principal, "release.gate.evaluate", idempotency_key, request_hash
        )
        if replay is not None:
            return cast(list[dict[str, Any]], replay["items"])
        candidate = self._require_visible(principal, "release_candidates", candidate_id)
        policy_decision = self._enforce_policy(
            principal,
            "release.gate.evaluate",
            "release_candidate",
            candidate_id,
            metadata={"environment": value.environment},
        )
        now = _now()
        gate_payloads = self._gate_statuses(candidate, value.environment)
        with self.db.transaction() as connection:
            for payload in gate_payloads:
                gate_result_id = str(uuid.uuid4())
                connection.execute(
                    """INSERT INTO release_gate_results(
                       id,candidate_id,gate_id,environment,status,reason,evidence_json,
                       evaluated_by,policy_decision_id,created_at,updated_at,version
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
                       ON CONFLICT(candidate_id, gate_id, environment) DO UPDATE SET
                       status=excluded.status,
                       reason=excluded.reason,
                       evidence_json=excluded.evidence_json,
                       evaluated_by=excluded.evaluated_by,
                       policy_decision_id=excluded.policy_decision_id,
                       created_at=excluded.created_at,
                       updated_at=excluded.updated_at,
                       version=release_gate_results.version + 1""",
                    (
                        gate_result_id,
                        candidate_id,
                        payload["gate_id"],
                        value.environment,
                        payload["status"],
                        payload["reason"],
                        _json_dumps(payload["evidence"]),
                        principal.id,
                        policy_decision["id"],
                        now,
                        now,
                    ),
                )
            connection.execute(
                "UPDATE release_candidates SET status='evaluated',updated_at=?,version=version+1 WHERE id=?",
                (now, candidate_id),
            )
        rows = self.db.fetch_all(
            """SELECT * FROM release_gate_results
               WHERE candidate_id=? AND environment=?
               ORDER BY gate_id""",
            (candidate_id, value.environment),
        )
        response = [self._gate_row(row) for row in rows]
        self._store_idempotency(
            principal,
            "release.gate.evaluate",
            idempotency_key or "",
            request_hash,
            {"items": response},
            resource_type="release_candidate",
            resource_id=candidate_id,
        )
        self._audit(
            principal,
            "release.gate.evaluate",
            "release_candidate",
            candidate_id,
            details={"environment": value.environment, "gate_count": len(response)},
        )
        return response

    def list_gates(self, principal: Principal, candidate_id: str) -> list[dict[str, Any]]:
        self._require_visible(principal, "release_candidates", candidate_id)
        return [
            self._gate_row(row)
            for row in self.db.fetch_all(
                "SELECT * FROM release_gate_results WHERE candidate_id=? ORDER BY environment, gate_id",
                (candidate_id,),
            )
        ]

    def approve_candidate(
        self,
        principal: Principal,
        candidate_id: str,
        value: ReleaseApprovalCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"candidate_id": candidate_id, **value.model_dump(mode="json")})
        replay = self._idempotent_response(
            principal, "release.approve", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        candidate = self._require_visible(principal, "release_candidates", candidate_id)
        if (
            value.expected_version is not None
            and int(candidate["version"]) != value.expected_version
        ):
            raise ReleaseStateError("optimistic lock version mismatch")
        if value.environment == "production" and principal.id == candidate["created_by"]:
            raise ReleaseStateError("release candidate creator cannot approve production promotion")
        self._enforce_policy(
            principal,
            "release.approve",
            "release_candidate",
            candidate_id,
            metadata={"environment": value.environment, "decision": value.decision},
        )
        approval_id = str(uuid.uuid4())
        now = _now()
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO release_approvals(
                   id,candidate_id,environment,decision,reason,approved_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,1)""",
                (
                    approval_id,
                    candidate_id,
                    value.environment,
                    value.decision,
                    value.reason,
                    principal.id,
                    now,
                    now,
                ),
            )
            if value.decision == "approved":
                connection.execute(
                    "UPDATE release_candidates SET status='approved',updated_at=?,version=version+1 WHERE id=?",
                    (now, candidate_id),
                )
        row = self.db.fetch_one("SELECT * FROM release_approvals WHERE id=?", (approval_id,))
        if row is None:
            raise ReleaseStateError("approval write failed")
        response = self._approval_row(row)
        self._store_idempotency(
            principal,
            "release.approve",
            idempotency_key or "",
            request_hash,
            response,
            resource_type="release_candidate",
            resource_id=candidate_id,
        )
        self._audit(
            principal,
            "release.approve",
            "release_candidate",
            candidate_id,
            details={"environment": value.environment, "decision": value.decision},
        )
        return response

    def request_exception(
        self,
        principal: Principal,
        candidate_id: str,
        value: ReleaseExceptionCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"candidate_id": candidate_id, **value.model_dump(mode="json")})
        operation = "release.exception.approve" if value.approve else "release.exception.request"
        replay = self._idempotent_response(principal, operation, idempotency_key, request_hash)
        if replay is not None:
            return replay
        self._require_visible(principal, "release_candidates", candidate_id)
        if value.expires_at <= datetime.now(UTC):
            raise ReleaseStateError("release exception must expire in the future")
        if value.risk == "critical" and value.approve:
            raise ReleaseStateError("critical gate exceptions require separation of duties")
        self._enforce_policy(
            principal,
            "release.exception.approve" if value.approve else "release.exception.request",
            "release_candidate",
            candidate_id,
            metadata={"gate_id": value.gate_id, "risk": value.risk},
        )
        exception_id = str(uuid.uuid4())
        now = _now()
        self.db.execute(
            """INSERT INTO release_exceptions(
               id,candidate_id,gate_id,reason,risk,scope,requested_by,approved_by,expires_at,
               compensating_controls_json,status,created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
            (
                exception_id,
                candidate_id,
                value.gate_id,
                value.reason,
                value.risk,
                value.scope,
                principal.id,
                principal.id if value.approve else None,
                value.expires_at.isoformat(),
                _json_dumps(value.compensating_controls),
                "approved" if value.approve else "requested",
                now,
                now,
            ),
        )
        row = self.db.fetch_one("SELECT * FROM release_exceptions WHERE id=?", (exception_id,))
        if row is None:
            raise ReleaseStateError("exception write failed")
        response = self._exception_row(row)
        self._store_idempotency(
            principal,
            operation,
            idempotency_key or "",
            request_hash,
            response,
            resource_type="release_candidate",
            resource_id=candidate_id,
        )
        self._audit(
            principal,
            operation,
            "release_candidate",
            candidate_id,
            details={"gate_id": value.gate_id, "risk": value.risk, "status": response["status"]},
        )
        return response

    def _has_active_exception(self, candidate_id: str, gate_id: str) -> bool:
        rows = self.db.fetch_all(
            """SELECT * FROM release_exceptions
               WHERE candidate_id=? AND gate_id=? AND status='approved'""",
            (candidate_id, gate_id),
        )
        now = datetime.now(UTC)
        for row in rows:
            expires_at = datetime.fromisoformat(row["expires_at"])
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at > now:
                return True
        return False

    def _gates_allow(self, candidate_id: str, environment: str) -> tuple[bool, list[str]]:
        rows = self.db.fetch_all(
            "SELECT * FROM release_gate_results WHERE candidate_id=? AND environment=?",
            (candidate_id, environment),
        )
        failures: list[str] = []
        for row in rows:
            if row["status"] == "failed" and not self._has_active_exception(
                candidate_id, row["gate_id"]
            ):
                failures.append(row["gate_id"])
        return not failures, failures

    def _previous_environment_deployed(self, candidate_id: str, environment: str) -> bool:
        index = ENVIRONMENT_ORDER.index(environment)
        if index == 0:
            return True
        previous = ENVIRONMENT_ORDER[index - 1]
        row = self.db.fetch_one(
            """SELECT * FROM release_environment_promotions
               WHERE candidate_id=? AND environment=? AND status='deployed'""",
            (candidate_id, previous),
        )
        return row is not None

    def promote_candidate(
        self,
        principal: Principal,
        candidate_id: str,
        value: EnvironmentPromotionCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"candidate_id": candidate_id, **value.model_dump(mode="json")})
        operation = f"release.promote.{value.environment}"
        replay = self._idempotent_response(principal, operation, idempotency_key, request_hash)
        if replay is not None:
            return replay
        candidate = self._require_visible(principal, "release_candidates", candidate_id)
        if (
            value.expected_version is not None
            and int(candidate["version"]) != value.expected_version
        ):
            raise ReleaseStateError("optimistic lock version mismatch")
        if not self._previous_environment_deployed(candidate_id, value.environment):
            raise ReleaseStateError(
                "environment promotion order must be development -> integration -> staging -> production"
            )
        existing_gates = self.db.fetch_one(
            "SELECT id FROM release_gate_results WHERE candidate_id=? AND environment=? LIMIT 1",
            (candidate_id, value.environment),
        )
        if existing_gates is None:
            self.evaluate_candidate(
                principal,
                candidate_id,
                ReleaseGateEvaluationRequest(environment=value.environment),
                idempotency_key=f"auto-gates:{idempotency_key}",
            )
        gates_ok, failed_gates = self._gates_allow(candidate_id, value.environment)
        if not gates_ok:
            raise ReleaseStateError(f"release gates failed: {', '.join(failed_gates)}")
        if value.environment == "production":
            approval = self.db.fetch_one(
                """SELECT * FROM release_approvals
                   WHERE candidate_id=? AND environment='production' AND decision='approved'
                   ORDER BY created_at DESC LIMIT 1""",
                (candidate_id,),
            )
            if approval is None:
                raise ReleaseStateError("production promotion requires human approval")
            if approval["approved_by"] == candidate["created_by"]:
                raise ReleaseStateError(
                    "release candidate creator cannot approve production promotion"
                )
        policy_decision = self._enforce_policy(
            principal,
            operation,
            "release_candidate",
            candidate_id,
            metadata={"environment": value.environment},
        )
        now = _now()
        promotion_id = str(uuid.uuid4())
        deployment_id = str(uuid.uuid4())
        health = dict(value.health)
        expected_snapshot = health.get(
            "approved_snapshot",
            {
                "image_digest": candidate["image_digest"],
                "configuration_hash": candidate["configuration_hash"],
                "replicas": health.get("replicas", 1),
                "resource_limits": health.get("resource_limits", {}),
                "security_context": health.get("security_context", {}),
                "secret_refs": health.get("secret_refs", []),
            },
        )
        health.setdefault("approved_snapshot", expected_snapshot)
        health.setdefault("current_snapshot", expected_snapshot)
        snapshot_hash = _digest(expected_snapshot)
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO release_environment_promotions(
                   id,candidate_id,environment,status,promoted_by,policy_decision_id,
                   created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,1)""",
                (
                    promotion_id,
                    candidate_id,
                    value.environment,
                    "deployed",
                    principal.id,
                    policy_decision["id"],
                    now,
                    now,
                ),
            )
            connection.execute(
                """INSERT INTO release_deployment_records(
                   id,promotion_id,candidate_id,environment,image_digest,canary_percentage,
                   status,health_json,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    deployment_id,
                    promotion_id,
                    candidate_id,
                    value.environment,
                    candidate["image_digest"],
                    value.canary_percentage,
                    "deployed",
                    _json_dumps(health),
                    now,
                    now,
                ),
            )
            connection.execute(
                """INSERT INTO release_configuration_snapshots(
                   id,candidate_id,environment,approved_snapshot_json,snapshot_hash,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,1)
                   ON CONFLICT(candidate_id, environment) DO UPDATE SET
                   approved_snapshot_json=excluded.approved_snapshot_json,
                   snapshot_hash=excluded.snapshot_hash,
                   created_at=excluded.created_at,
                   updated_at=excluded.updated_at,
                   version=release_configuration_snapshots.version + 1""",
                (
                    str(uuid.uuid4()),
                    candidate_id,
                    value.environment,
                    _json_dumps(expected_snapshot),
                    snapshot_hash,
                    now,
                    now,
                ),
            )
            connection.execute(
                "UPDATE release_candidates SET status='deployed',updated_at=?,version=version+1 WHERE id=?",
                (now, candidate_id),
            )
        promotion = self.db.fetch_one(
            "SELECT * FROM release_environment_promotions WHERE id=?", (promotion_id,)
        )
        deployment = self.db.fetch_one(
            "SELECT * FROM release_deployment_records WHERE id=?", (deployment_id,)
        )
        if promotion is None or deployment is None:
            raise ReleaseStateError("promotion write failed")
        response = self._promotion_row(promotion)
        response["deployment"] = self._deployment_row(deployment)
        self._store_idempotency(
            principal,
            operation,
            idempotency_key or "",
            request_hash,
            response,
            resource_type="release_candidate",
            resource_id=candidate_id,
        )
        self._audit(
            principal,
            operation,
            "release_candidate",
            candidate_id,
            details={
                "environment": value.environment,
                "deployment_id": deployment_id,
                "image_digest": candidate["image_digest"],
            },
        )
        return response

    def get_deployment(self, principal: Principal, deployment_id: str) -> dict[str, Any]:
        row = self._require_visible(principal, "release_deployment_records", deployment_id)
        return self._deployment_row(row)

    def rollback_deployment(
        self,
        principal: Principal,
        deployment_id: str,
        value: RollbackCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"deployment_id": deployment_id, **value.model_dump(mode="json")})
        replay = self._idempotent_response(
            principal, "release.rollback", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        deployment = self._require_visible(principal, "release_deployment_records", deployment_id)
        self._enforce_policy(
            principal,
            "release.rollback",
            "release_deployment",
            deployment_id,
            metadata={"environment": deployment["environment"]},
        )
        rollback_id = str(uuid.uuid4())
        now = _now()
        approved_by = value.approved_by or principal.id
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO release_rollback_records(
                   id,deployment_id,candidate_id,environment,reason,requested_by,approved_by,
                   status,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    rollback_id,
                    deployment_id,
                    deployment["candidate_id"],
                    deployment["environment"],
                    value.reason,
                    principal.id,
                    approved_by,
                    "completed",
                    now,
                    now,
                ),
            )
            connection.execute(
                "UPDATE release_deployment_records SET status='rolled_back',updated_at=?,version=version+1 WHERE id=?",
                (now, deployment_id),
            )
            connection.execute(
                "UPDATE release_candidates SET status='rolled_back',updated_at=?,version=version+1 WHERE id=?",
                (now, deployment["candidate_id"]),
            )
        row = self.db.fetch_one("SELECT * FROM release_rollback_records WHERE id=?", (rollback_id,))
        if row is None:
            raise ReleaseStateError("rollback write failed")
        response = self._rollback_row(row)
        self._store_idempotency(
            principal,
            "release.rollback",
            idempotency_key or "",
            request_hash,
            response,
            resource_type="release_deployment",
            resource_id=deployment_id,
        )
        self._audit(
            principal,
            "release.rollback",
            "release_deployment",
            deployment_id,
            details={
                "candidate_id": deployment["candidate_id"],
                "environment": deployment["environment"],
            },
        )
        return response

    def detect_drift(self, principal: Principal, deployment_id: str) -> dict[str, Any]:
        deployment = self._require_visible(principal, "release_deployment_records", deployment_id)
        self._enforce_policy(
            principal,
            "release.drift.review",
            "release_deployment",
            deployment_id,
            metadata={"environment": deployment["environment"]},
        )
        health = _json(deployment["health_json"], {})
        expected = health.get("approved_snapshot", {})
        actual = health.get("current_snapshot", expected)
        drift_types = [
            drift_type
            for drift_type, field_name in DRIFT_FIELDS.items()
            if expected.get(field_name) != actual.get(field_name)
        ]
        status = "drift_detected" if drift_types else "healthy"
        drift_id = str(uuid.uuid4())
        now = _now()
        self.db.execute(
            """INSERT INTO release_drift_detection_results(
               id,deployment_id,status,drift_types_json,expected_json,actual_json,reviewed_by,created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,?,?,1)""",
            (
                drift_id,
                deployment_id,
                status,
                _json_dumps(drift_types),
                _json_dumps(expected),
                _json_dumps(actual),
                principal.id,
                now,
                now,
            ),
        )
        row = self.db.fetch_one(
            "SELECT * FROM release_drift_detection_results WHERE id=?", (drift_id,)
        )
        if row is None:
            raise ReleaseStateError("drift result write failed")
        response = self._drift_row(row)
        self._audit(
            principal,
            "release.drift.review",
            "release_deployment",
            deployment_id,
            details={"status": status, "drift_types": drift_types},
        )
        return response

    def generate_compliance_package(
        self,
        principal: Principal,
        candidate_id: str,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"candidate_id": candidate_id})
        replay = self._idempotent_response(
            principal, "release.compliance.generate", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        candidate = self.get_candidate(principal, candidate_id)
        self._enforce_policy(
            principal,
            "release.compliance.generate",
            "release_candidate",
            candidate_id,
        )
        contents = {
            "candidate": {
                key: candidate[key]
                for key in (
                    "id",
                    "source_commit",
                    "image_digest",
                    "sbom_digest",
                    "provenance_digest",
                    "signature_digest",
                    "configuration_hash",
                    "helm_chart_digest",
                    "freeze_hash",
                )
            },
            "artifact": {
                "digest": candidate["artifact"]["digest"],
                "source_commit": candidate["artifact"]["source_commit"],
                "sbom_count": len(candidate["artifact"]["sbom_documents"]),
                "signature_count": len(candidate["artifact"]["signature_records"]),
                "provenance_count": len(candidate["artifact"]["provenance_statements"]),
            },
            "gates": candidate["gates"],
            "approvals": candidate["approvals"],
            "exceptions": candidate["exceptions"],
            "promotions": candidate["promotions"],
            "deployments": candidate["deployments"],
        }
        package_digest = _digest(contents)
        package_id = str(uuid.uuid4())
        now = _now()
        self.db.execute(
            """INSERT INTO release_compliance_evidence_packages(
               id,candidate_id,package_digest,contents_json,generated_by,created_at,updated_at,version
               ) VALUES(?,?,?,?,?,?,?,1)""",
            (
                package_id,
                candidate_id,
                package_digest,
                _json_dumps(contents),
                principal.id,
                now,
                now,
            ),
        )
        row = self.db.fetch_one(
            "SELECT * FROM release_compliance_evidence_packages WHERE id=?", (package_id,)
        )
        if row is None:
            raise ReleaseStateError("compliance package write failed")
        response = self._compliance_row(row)
        self._store_idempotency(
            principal,
            "release.compliance.generate",
            idempotency_key or "",
            request_hash,
            response,
            resource_type="release_candidate",
            resource_id=candidate_id,
        )
        self._audit(
            principal,
            "release.compliance.generate",
            "release_candidate",
            candidate_id,
            details={"package_digest": package_digest},
        )
        return response
