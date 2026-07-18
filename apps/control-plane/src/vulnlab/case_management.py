from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from .audit import AuditService
from .policy import PolicyService
from .repository import ControlPlaneRepository
from .schemas import (
    CaseDispositionCreate,
    CaseFindingCreate,
    CaseReportCreate,
    PolicyEvaluationRequest,
    RemediationDecisionCreate,
    RemediationImplementationCreate,
    RemediationProposalCreate,
    RetestRequestCreate,
    VulnerabilityCaseCreate,
    VulnerabilityCasePatch,
)
from .security import Principal
from .validation_execution import TERMINAL_STATUSES, ValidationExecutionService

CASE_TERMINAL_STATUSES = frozenset(
    {"REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE", "INCONCLUSIVE", "CLOSED"}
)
CASE_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "DRAFT": frozenset({"TRIAGE"}),
    "TRIAGE": frozenset({"VALIDATION_PENDING"}),
    "VALIDATION_PENDING": frozenset({"VALIDATED", "FALSE_POSITIVE", "INCONCLUSIVE"}),
    "VALIDATED": frozenset({"REMEDIATION_PLANNED", "ACCEPTED_RISK"}),
    "REMEDIATION_PLANNED": frozenset({"REMEDIATION_IN_PROGRESS", "ACCEPTED_RISK"}),
    "REMEDIATION_IN_PROGRESS": frozenset({"RETEST_PENDING", "ACCEPTED_RISK"}),
    "RETEST_PENDING": frozenset({"REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE", "INCONCLUSIVE"}),
    "REMEDIATED": frozenset({"CLOSED"}),
    "ACCEPTED_RISK": frozenset({"CLOSED"}),
    "FALSE_POSITIVE": frozenset({"CLOSED"}),
    "INCONCLUSIVE": frozenset({"CLOSED"}),
    "CLOSED": frozenset(),
}


class CaseManagementError(ValueError):
    pass


class CaseStateError(CaseManagementError):
    pass


class CaseIsolationError(CaseManagementError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _future(hours: int) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).isoformat()


def _json(value: str | None, default: Any) -> Any:
    if value is None or value == "":
        return default
    return json.loads(value)


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _bool(value: Any) -> bool:
    return bool(int(value)) if isinstance(value, int | str) else bool(value)


class CaseManagementService:
    def __init__(
        self,
        db: ControlPlaneRepository,
        policy: PolicyService,
        audit: AuditService,
        validation_execution: ValidationExecutionService,
    ):
        self.db = db
        self.policy = policy
        self.audit = audit
        self.validation_execution = validation_execution
        self._write_lock = threading.RLock()

    def _case_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "title": row["title"],
            "summary": row["summary"],
            "severity": row["severity"],
            "status": row["status"],
            "source": row["source"],
            "external_ref": row["external_ref"],
            "metadata": _json(row["metadata_json"], {}),
            "created_by": row["created_by"],
            "updated_by": row["updated_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def _finding_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "case_id": row["case_id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "validation_execution_id": row["validation_execution_id"],
            "evidence_id": row["evidence_id"],
            "title": row["title"],
            "description": row["description"],
            "affected_component": row["affected_component"],
            "risk_level": row["risk_level"],
            "status": row["status"],
            "metadata": _json(row["metadata_json"], {}),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def _proposal_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "case_id": row["case_id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "source": row["source"],
            "title": row["title"],
            "description": row["description"],
            "risk_level": row["risk_level"],
            "knowledge_refs": _json(row["knowledge_refs_json"], []),
            "model_invocation_id": row["model_invocation_id"],
            "provenance": _json(row["provenance_json"], {}),
            "status": row["status"],
            "proposed_by": row["proposed_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def _decision_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "proposal_id": row["proposal_id"],
            "case_id": row["case_id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "decision": row["decision"],
            "reason": row["reason"],
            "automated": _bool(row["automated"]),
            "decided_by": row["decided_by"],
            "decided_at": row["decided_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def _implementation_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "decision_id": row["decision_id"],
            "proposal_id": row["proposal_id"],
            "case_id": row["case_id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "implementation_ref": row["implementation_ref"],
            "description": row["description"],
            "implemented_by": row["implemented_by"],
            "implemented_at": row["implemented_at"],
            "verification_notes": row["verification_notes"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def _retest_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "case_id": row["case_id"],
            "finding_id": row["finding_id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "original_execution_id": row["original_execution_id"],
            "remediation_implementation_id": row["remediation_implementation_id"],
            "retest_execution_id": row["retest_execution_id"],
            "status": row["status"],
            "template_id": row["template_id"],
            "template_version": row["template_version"],
            "template_version_changed": _bool(row["template_version_changed"]),
            "requested_by": row["requested_by"],
            "requested_at": row["requested_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def _comparison_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "retest_id": row["retest_id"],
            "case_id": row["case_id"],
            "finding_id": row["finding_id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "original_execution_id": row["original_execution_id"],
            "retest_execution_id": row["retest_execution_id"],
            "result": row["result"],
            "initial_status": row["initial_status"],
            "retest_status": row["retest_status"],
            "success_condition_diff": _json(row["success_condition_diff_json"], {}),
            "key_response_diff": _json(row["key_response_diff_json"], {}),
            "component_version_diff": _json(row["component_version_diff_json"], {}),
            "evidence_sha256": _json(row["evidence_sha256_json"], {}),
            "risk_level_change": row["risk_level_change"],
            "residual_risk": row["residual_risk"],
            "recommendation": row["recommendation"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def _disposition_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "case_id": row["case_id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "disposition": row["disposition"],
            "reason": row["reason"],
            "residual_risk": row["residual_risk"],
            "human_confirmed": _bool(row["human_confirmed"]),
            "decided_by": row["decided_by"],
            "decided_at": row["decided_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def _report_row(self, row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "case_id": row["case_id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "title": row["title"],
            "report": _json(row["report_json"], {}),
            "generated_by": row["generated_by"],
            "generated_at": row["generated_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

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
            raise CaseStateError("Idempotency-Key is required and must be at most 200 characters")
        row = self.db.fetch_one(
            """SELECT * FROM task_idempotency_records
               WHERE principal_id=? AND operation=? AND idempotency_key=?""",
            (principal.id, operation, idempotency_key),
        )
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise CaseStateError("Idempotency-Key was reused with a different case request")
        if row["response_json"]:
            return _json(row["response_json"], {})
        raise CaseStateError("idempotent case request is still processing")

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

    def _get_case_row(self, principal: Principal, case_id: str) -> Any:
        row = self.db.fetch_one("SELECT * FROM vulnerability_cases WHERE id=?", (case_id,))
        if row is None:
            raise KeyError("vulnerability case not found")
        if principal.role.value != "admin" and row["tenant_id"] != principal.id:
            raise KeyError("vulnerability case not found")
        return row

    def _require_mutable(self, row: Any) -> None:
        if row["status"] == "CLOSED":
            raise CaseStateError("closed cases cannot be modified")

    def _assert_same_case_scope(self, case_row: Any, row: Any, resource_name: str) -> None:
        if row["tenant_id"] != case_row["tenant_id"] or row["project_id"] != case_row["project_id"]:
            raise CaseIsolationError(f"{resource_name} belongs to another tenant or project")

    def _transition_case(
        self,
        principal: Principal,
        case_row: Any,
        target_status: str,
        *,
        expected_version: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        current = case_row["status"]
        if target_status == current:
            return self._case_row(case_row)
        if target_status not in CASE_ALLOWED_TRANSITIONS.get(str(current), frozenset()):
            raise CaseStateError(f"invalid case transition {current} -> {target_status}")
        version = expected_version if expected_version is not None else int(case_row["version"])
        now = _now()
        with self.db.transaction() as connection:
            updated = connection.execute(
                """UPDATE vulnerability_cases
                   SET status=?,updated_by=?,updated_at=?,version=version+1
                   WHERE id=? AND tenant_id=? AND version=?""",
                (target_status, principal.id, now, case_row["id"], case_row["tenant_id"], version),
            ).rowcount
        if updated != 1:
            raise CaseStateError("case optimistic lock failed")
        self._audit(
            principal,
            "case.transition",
            "vulnerability_case",
            case_row["id"],
            details={
                "from_status": current,
                "to_status": target_status,
                **(details or {}),
            },
        )
        return self.get_case(principal, case_row["id"])

    def _auto_transition(self, principal: Principal, case_id: str, target_status: str) -> None:
        row = self._get_case_row(principal, case_id)
        if target_status in CASE_ALLOWED_TRANSITIONS.get(str(row["status"]), frozenset()):
            self._transition_case(principal, row, target_status, details={"automatic": True})

    def create_case(
        self,
        principal: Principal,
        value: VulnerabilityCaseCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest(value.model_dump(mode="json"))
        with self._write_lock:
            existing = self._idempotent_response(
                principal, "case.create", idempotency_key, request_hash
            )
            if existing is not None:
                return existing
            decision = self._enforce_policy(
                principal,
                "case.create",
                "vulnerability_case",
                "new",
                metadata={"project_id": value.project_id, "severity": value.severity},
            )
            case_id = str(uuid.uuid4())
            now = _now()
            response: dict[str, Any]
            with self.db.transaction() as connection:
                connection.execute(
                    """INSERT INTO vulnerability_cases(
                       id,tenant_id,project_id,title,summary,severity,status,source,
                       external_ref,metadata_json,created_by,updated_by,created_at,updated_at,version
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                    (
                        case_id,
                        principal.id,
                        value.project_id,
                        value.title,
                        value.summary,
                        value.severity,
                        "DRAFT",
                        value.source,
                        value.external_ref,
                        _json_dumps(value.metadata),
                        principal.id,
                        principal.id,
                        now,
                        now,
                    ),
                )
            response = self.get_case(principal, case_id)
            self._store_idempotency(
                principal,
                "case.create",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="vulnerability_case",
                resource_id=case_id,
            )
            self._audit(
                principal,
                "case.create",
                "vulnerability_case",
                case_id,
                details={"policy_decision_id": decision["id"], "project_id": value.project_id},
            )
            return response

    def list_cases(
        self,
        principal: Principal,
        *,
        limit: int = 100,
        project_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if principal.role.value != "admin":
            clauses.append("tenant_id=?")
            params.append(principal.id)
        if project_id:
            clauses.append("project_id=?")
            params.append(project_id)
        if status:
            clauses.append("status=?")
            params.append(status)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.db.fetch_all(
            f"""SELECT * FROM vulnerability_cases
                {where}
                ORDER BY updated_at DESC,id DESC LIMIT ?""",
            (*params, min(max(limit, 1), 500)),
        )
        return [self._case_row(row) for row in rows]

    def get_case(self, principal: Principal, case_id: str) -> dict[str, Any]:
        return self._case_row(self._get_case_row(principal, case_id))

    def get_case_detail(self, principal: Principal, case_id: str) -> dict[str, Any]:
        case = self.get_case(principal, case_id)
        tenant_id = case["tenant_id"]
        rows = {
            "findings": self.list_findings(principal, case_id),
            "remediation_proposals": self.list_proposals(principal, case_id),
            "remediation_decisions": [
                self._decision_row(row)
                for row in self.db.fetch_all(
                    """SELECT * FROM remediation_decisions
                       WHERE tenant_id=? AND case_id=? ORDER BY decided_at DESC,id DESC""",
                    (tenant_id, case_id),
                )
            ],
            "remediation_implementations": [
                self._implementation_row(row)
                for row in self.db.fetch_all(
                    """SELECT * FROM remediation_implementations
                       WHERE tenant_id=? AND case_id=? ORDER BY created_at DESC,id DESC""",
                    (tenant_id, case_id),
                )
            ],
            "retests": [
                self._retest_row(row)
                for row in self.db.fetch_all(
                    """SELECT * FROM retest_requests
                       WHERE tenant_id=? AND case_id=? ORDER BY created_at DESC,id DESC""",
                    (tenant_id, case_id),
                )
            ],
            "comparisons": [
                self._comparison_row(row)
                for row in self.db.fetch_all(
                    """SELECT * FROM validation_comparisons
                       WHERE tenant_id=? AND case_id=? ORDER BY created_at DESC,id DESC""",
                    (tenant_id, case_id),
                )
            ],
            "dispositions": [
                self._disposition_row(row)
                for row in self.db.fetch_all(
                    """SELECT * FROM case_dispositions
                       WHERE tenant_id=? AND case_id=? ORDER BY decided_at DESC,id DESC""",
                    (tenant_id, case_id),
                )
            ],
            "reports": [
                self._report_row(row)
                for row in self.db.fetch_all(
                    """SELECT * FROM case_reports
                       WHERE tenant_id=? AND case_id=? ORDER BY generated_at DESC,id DESC""",
                    (tenant_id, case_id),
                )
            ],
            "audit_events": [
                {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "actor_id": row["actor_id"],
                    "action": row["action"],
                    "resource_type": row["resource_type"],
                    "resource_id": row["resource_id"],
                    "outcome": row["outcome"],
                    "details": _json(row["details_json"], {}),
                }
                for row in self.db.fetch_all(
                    """SELECT * FROM audit_logs
                       WHERE resource_id=? OR details_json LIKE ?
                       ORDER BY id DESC LIMIT 100""",
                    (case_id, f"%{case_id}%"),
                )
            ],
        }
        return {"case": case, **rows}

    def update_case(
        self,
        principal: Principal,
        case_id: str,
        value: VulnerabilityCasePatch,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"case_id": case_id, **value.model_dump(mode="json")})
        with self._write_lock:
            existing = (
                self._idempotent_response(principal, "case.update", idempotency_key, request_hash)
                if idempotency_key
                else None
            )
            if existing is not None:
                return existing
            case_row = self._get_case_row(principal, case_id)
            self._require_mutable(case_row)
            action = "case.confirm" if value.status == "VALIDATED" else "case.update"
            decision = self._enforce_policy(
                principal,
                action,
                "vulnerability_case",
                case_id,
                metadata={
                    "expected_version": value.expected_version,
                    "target_status": value.status,
                },
            )
            if value.status is not None and value.status != case_row["status"]:
                updated_case = self._transition_case(
                    principal,
                    case_row,
                    value.status,
                    expected_version=value.expected_version,
                    details={"policy_decision_id": decision["id"]},
                )
                case_row = self._get_case_row(principal, case_id)
                expected_version = updated_case["version"]
            else:
                expected_version = value.expected_version
            updates: list[str] = []
            params: list[Any] = []
            if value.title is not None:
                updates.append("title=?")
                params.append(value.title)
            if value.summary is not None:
                updates.append("summary=?")
                params.append(value.summary)
            if value.severity is not None:
                updates.append("severity=?")
                params.append(value.severity)
            if value.metadata is not None:
                updates.append("metadata_json=?")
                params.append(_json_dumps(value.metadata))
            if updates:
                now = _now()
                with self.db.transaction() as connection:
                    updated = connection.execute(
                        f"""UPDATE vulnerability_cases
                            SET {",".join(updates)},updated_by=?,updated_at=?,version=version+1
                            WHERE id=? AND tenant_id=? AND version=?""",
                        (
                            *params,
                            principal.id,
                            now,
                            case_id,
                            case_row["tenant_id"],
                            expected_version,
                        ),
                    ).rowcount
                if updated != 1:
                    raise CaseStateError("case optimistic lock failed")
            response = self.get_case(principal, case_id)
            if idempotency_key:
                self._store_idempotency(
                    principal,
                    "case.update",
                    idempotency_key,
                    request_hash,
                    response,
                    resource_type="vulnerability_case",
                    resource_id=case_id,
                )
            self._audit(
                principal,
                "case.update",
                "vulnerability_case",
                case_id,
                details={"policy_decision_id": decision["id"], "status": response["status"]},
            )
            return response

    def _validate_execution_scope(self, case_row: Any, execution_id: str) -> dict[str, Any]:
        execution = self.validation_execution.get(execution_id)
        if execution["tenant_id"] != case_row["tenant_id"]:
            raise CaseIsolationError("validation execution belongs to another tenant")
        return execution

    def create_finding(
        self,
        principal: Principal,
        case_id: str,
        value: CaseFindingCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"case_id": case_id, **value.model_dump(mode="json")})
        with self._write_lock:
            existing = self._idempotent_response(
                principal, "case.finding.create", idempotency_key, request_hash
            )
            if existing is not None:
                return existing
            case_row = self._get_case_row(principal, case_id)
            self._require_mutable(case_row)
            project_id = value.project_id or case_row["project_id"]
            if project_id != case_row["project_id"]:
                raise CaseIsolationError("finding project_id must match the case project_id")
            execution: dict[str, Any] | None = None
            if value.validation_execution_id:
                execution = self._validate_execution_scope(case_row, value.validation_execution_id)
            if value.status == "VALIDATED":
                if execution is None or execution["status"] != "SUCCEEDED":
                    raise CaseStateError(
                        "validated findings require a succeeded validation execution"
                    )
                if execution["review_decision"] != "accepted":
                    raise CaseStateError("validated findings require accepted validation evidence")
            if value.evidence_id:
                evidence = self.db.fetch_one(
                    "SELECT * FROM validation_execution_evidence WHERE id=?", (value.evidence_id,)
                )
                if evidence is None:
                    raise KeyError("validation evidence not found")
                if execution is not None and evidence["execution_id"] != execution["id"]:
                    raise CaseIsolationError("evidence does not belong to the supplied execution")
            decision = self._enforce_policy(
                principal,
                "case.update",
                "vulnerability_case",
                case_id,
                metadata={"finding_status": value.status},
            )
            finding_id = str(uuid.uuid4())
            now = _now()
            self.db.execute(
                """INSERT INTO case_findings(
                   id,case_id,tenant_id,project_id,validation_execution_id,evidence_id,
                   title,description,affected_component,risk_level,status,metadata_json,
                   created_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    finding_id,
                    case_id,
                    case_row["tenant_id"],
                    project_id,
                    value.validation_execution_id,
                    value.evidence_id,
                    value.title,
                    value.description,
                    value.affected_component,
                    value.risk_level,
                    value.status,
                    _json_dumps(value.metadata),
                    principal.id,
                    now,
                    now,
                ),
            )
            response = self.get_finding(principal, finding_id)
            self._store_idempotency(
                principal,
                "case.finding.create",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="case_finding",
                resource_id=finding_id,
            )
            self._audit(
                principal,
                "case.finding.create",
                "vulnerability_case",
                case_id,
                details={"finding_id": finding_id, "policy_decision_id": decision["id"]},
            )
            return response

    def get_finding(self, principal: Principal, finding_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM case_findings WHERE id=?", (finding_id,))
        if row is None:
            raise KeyError("case finding not found")
        self._get_case_row(principal, row["case_id"])
        return self._finding_row(row)

    def list_findings(self, principal: Principal, case_id: str) -> list[dict[str, Any]]:
        case_row = self._get_case_row(principal, case_id)
        rows = self.db.fetch_all(
            """SELECT * FROM case_findings
               WHERE tenant_id=? AND case_id=? ORDER BY created_at DESC,id DESC""",
            (case_row["tenant_id"], case_id),
        )
        return [self._finding_row(row) for row in rows]

    def create_proposal(
        self,
        principal: Principal,
        case_id: str,
        value: RemediationProposalCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"case_id": case_id, **value.model_dump(mode="json")})
        with self._write_lock:
            existing = self._idempotent_response(
                principal, "remediation.propose", idempotency_key, request_hash
            )
            if existing is not None:
                return existing
            case_row = self._get_case_row(principal, case_id)
            self._require_mutable(case_row)
            decision = self._enforce_policy(
                principal,
                "remediation.propose",
                "vulnerability_case",
                case_id,
                metadata={"source": value.source, "risk_level": value.risk_level},
            )
            proposal_id = str(uuid.uuid4())
            now = _now()
            self.db.execute(
                """INSERT INTO remediation_proposals(
                   id,case_id,tenant_id,project_id,source,title,description,risk_level,
                   knowledge_refs_json,model_invocation_id,provenance_json,status,
                   proposed_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    proposal_id,
                    case_id,
                    case_row["tenant_id"],
                    case_row["project_id"],
                    value.source,
                    value.title,
                    value.description,
                    value.risk_level,
                    _json_dumps(value.knowledge_refs),
                    value.model_invocation_id,
                    _json_dumps(value.provenance),
                    "PROPOSED",
                    principal.id,
                    now,
                    now,
                ),
            )
            self._auto_transition(principal, case_id, "REMEDIATION_PLANNED")
            response = self.get_proposal(principal, proposal_id)
            self._store_idempotency(
                principal,
                "remediation.propose",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="remediation_proposal",
                resource_id=proposal_id,
            )
            self._audit(
                principal,
                "remediation.propose",
                "vulnerability_case",
                case_id,
                details={
                    "proposal_id": proposal_id,
                    "policy_decision_id": decision["id"],
                    "source": value.source,
                },
            )
            return response

    def get_proposal(self, principal: Principal, proposal_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM remediation_proposals WHERE id=?", (proposal_id,))
        if row is None:
            raise KeyError("remediation proposal not found")
        self._get_case_row(principal, row["case_id"])
        return self._proposal_row(row)

    def list_proposals(self, principal: Principal, case_id: str) -> list[dict[str, Any]]:
        case_row = self._get_case_row(principal, case_id)
        rows = self.db.fetch_all(
            """SELECT * FROM remediation_proposals
               WHERE tenant_id=? AND case_id=? ORDER BY created_at DESC,id DESC""",
            (case_row["tenant_id"], case_id),
        )
        return [self._proposal_row(row) for row in rows]

    def decide_proposal(
        self,
        principal: Principal,
        proposal_id: str,
        value: RemediationDecisionCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"proposal_id": proposal_id, **value.model_dump(mode="json")})
        with self._write_lock:
            existing = self._idempotent_response(
                principal, "remediation.approve", idempotency_key, request_hash
            )
            if existing is not None:
                return existing
            proposal_row = self.db.fetch_one(
                "SELECT * FROM remediation_proposals WHERE id=?", (proposal_id,)
            )
            if proposal_row is None:
                raise KeyError("remediation proposal not found")
            case_row = self._get_case_row(principal, proposal_row["case_id"])
            self._require_mutable(case_row)
            if value.automated and value.decision == "APPROVED":
                raise CaseStateError("automated remediation decisions cannot approve proposals")
            if (
                value.decision == "APPROVED"
                and proposal_row["risk_level"] == "high"
                and proposal_row["proposed_by"] == principal.id
            ):
                raise CaseStateError("high-risk remediation approval requires separation of duties")
            decision_record = self._enforce_policy(
                principal,
                "remediation.approve",
                "remediation_proposal",
                proposal_id,
                metadata={"decision": value.decision, "automated": value.automated},
            )
            decision_id = str(uuid.uuid4())
            now = _now()
            with self.db.transaction() as connection:
                connection.execute(
                    """INSERT INTO remediation_decisions(
                       id,proposal_id,case_id,tenant_id,project_id,decision,reason,automated,
                       decided_by,decided_at,created_at,updated_at,version
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                    (
                        decision_id,
                        proposal_id,
                        proposal_row["case_id"],
                        proposal_row["tenant_id"],
                        proposal_row["project_id"],
                        value.decision,
                        value.reason,
                        int(value.automated),
                        principal.id,
                        now,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """UPDATE remediation_proposals
                       SET status=?,updated_at=?,version=version+1
                       WHERE id=? AND tenant_id=?""",
                    (value.decision, now, proposal_id, proposal_row["tenant_id"]),
                )
            response = self.get_decision(principal, decision_id)
            self._store_idempotency(
                principal,
                "remediation.approve",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="remediation_decision",
                resource_id=decision_id,
            )
            self._audit(
                principal,
                "remediation.decision",
                "remediation_proposal",
                proposal_id,
                details={"decision_id": decision_id, "policy_decision_id": decision_record["id"]},
            )
            return response

    def get_decision(self, principal: Principal, decision_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM remediation_decisions WHERE id=?", (decision_id,))
        if row is None:
            raise KeyError("remediation decision not found")
        self._get_case_row(principal, row["case_id"])
        return self._decision_row(row)

    def create_implementation(
        self,
        principal: Principal,
        decision_id: str,
        value: RemediationImplementationCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"decision_id": decision_id, **value.model_dump(mode="json")})
        with self._write_lock:
            existing = self._idempotent_response(
                principal, "remediation.implement", idempotency_key, request_hash
            )
            if existing is not None:
                return existing
            decision_row = self.db.fetch_one(
                "SELECT * FROM remediation_decisions WHERE id=?", (decision_id,)
            )
            if decision_row is None:
                raise KeyError("remediation decision not found")
            case_row = self._get_case_row(principal, decision_row["case_id"])
            self._require_mutable(case_row)
            if decision_row["decision"] != "APPROVED":
                raise CaseStateError("only approved remediation decisions can be implemented")
            policy_decision = self._enforce_policy(
                principal,
                "remediation.implement",
                "remediation_decision",
                decision_id,
                metadata={"implementation_ref": value.implementation_ref},
            )
            implementation_id = str(uuid.uuid4())
            now = _now()
            implemented_at = (
                value.implemented_at.isoformat() if value.implemented_at is not None else now
            )
            self.db.execute(
                """INSERT INTO remediation_implementations(
                   id,decision_id,proposal_id,case_id,tenant_id,project_id,
                   implementation_ref,description,implemented_by,implemented_at,
                   verification_notes,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    implementation_id,
                    decision_id,
                    decision_row["proposal_id"],
                    decision_row["case_id"],
                    decision_row["tenant_id"],
                    decision_row["project_id"],
                    value.implementation_ref,
                    value.description,
                    principal.id,
                    implemented_at,
                    value.verification_notes,
                    now,
                    now,
                ),
            )
            self._auto_transition(principal, decision_row["case_id"], "REMEDIATION_IN_PROGRESS")
            response = self.get_implementation(principal, implementation_id)
            self._store_idempotency(
                principal,
                "remediation.implement",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="remediation_implementation",
                resource_id=implementation_id,
            )
            self._audit(
                principal,
                "remediation.implement",
                "remediation_decision",
                decision_id,
                details={
                    "implementation_id": implementation_id,
                    "policy_decision_id": policy_decision["id"],
                },
            )
            return response

    def get_implementation(self, principal: Principal, implementation_id: str) -> dict[str, Any]:
        row = self.db.fetch_one(
            "SELECT * FROM remediation_implementations WHERE id=?", (implementation_id,)
        )
        if row is None:
            raise KeyError("remediation implementation not found")
        self._get_case_row(principal, row["case_id"])
        return self._implementation_row(row)

    def create_retest(
        self,
        principal: Principal,
        case_id: str,
        value: RetestRequestCreate,
        *,
        idempotency_key: str | None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        request_hash = _digest({"case_id": case_id, **value.model_dump(mode="json")})
        with self._write_lock:
            existing = self._idempotent_response(
                principal, "validation.retest", idempotency_key, request_hash
            )
            if existing is not None:
                return existing
            case_row = self._get_case_row(principal, case_id)
            self._require_mutable(case_row)
            finding = self.db.fetch_one(
                "SELECT * FROM case_findings WHERE id=? AND case_id=?",
                (value.finding_id, case_id),
            )
            if finding is None:
                raise KeyError("case finding not found")
            implementation = self.db.fetch_one(
                """SELECT * FROM remediation_implementations
                   WHERE id=? AND case_id=?""",
                (value.remediation_implementation_id, case_id),
            )
            if implementation is None:
                raise CaseStateError("retest requires a remediation implementation record")
            original = self._validate_execution_scope(case_row, value.original_execution_id)
            if original["status"] not in TERMINAL_STATUSES:
                raise CaseStateError("retest requires a terminal original validation execution")
            self._assert_same_case_scope(case_row, finding, "finding")
            self._assert_same_case_scope(case_row, implementation, "remediation implementation")
            policy_decision = self._enforce_policy(
                principal,
                "validation.retest",
                "vulnerability_case",
                case_id,
                metadata={
                    "finding_id": value.finding_id,
                    "original_execution_id": value.original_execution_id,
                    "implementation_id": value.remediation_implementation_id,
                },
            )
            retest_execution = self.validation_execution.create(
                principal,
                original["plan_id"],
                idempotency_key=f"p10-retest:{idempotency_key}",
                template_id=original["template_id"],
                request_id=request_id,
            )
            retest_id = str(uuid.uuid4())
            now = _now()
            template_version_changed = int(
                retest_execution["template_version"] != original["template_version"]
            )
            self.db.execute(
                """INSERT INTO retest_requests(
                   id,case_id,finding_id,tenant_id,project_id,original_execution_id,
                   remediation_implementation_id,retest_execution_id,status,template_id,
                   template_version,template_version_changed,requested_by,requested_at,
                   created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    retest_id,
                    case_id,
                    value.finding_id,
                    case_row["tenant_id"],
                    case_row["project_id"],
                    value.original_execution_id,
                    value.remediation_implementation_id,
                    retest_execution["id"],
                    "QUEUED",
                    retest_execution["template_id"],
                    retest_execution["template_version"],
                    template_version_changed,
                    principal.id,
                    now,
                    now,
                    now,
                ),
            )
            self._auto_transition(principal, case_id, "RETEST_PENDING")
            response = self.get_retest(principal, retest_id)
            self._store_idempotency(
                principal,
                "validation.retest",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="retest_request",
                resource_id=retest_id,
            )
            self._audit(
                principal,
                "validation.retest",
                "vulnerability_case",
                case_id,
                details={
                    "retest_id": retest_id,
                    "retest_execution_id": retest_execution["id"],
                    "policy_decision_id": policy_decision["id"],
                },
            )
            return response

    def get_retest(self, principal: Principal, retest_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM retest_requests WHERE id=?", (retest_id,))
        if row is None:
            raise KeyError("retest request not found")
        self._get_case_row(principal, row["case_id"])
        return self._retest_row(row)

    def _execution_evidence_sha(self, execution_id: str) -> list[str]:
        return [
            str(row["content_sha256"])
            for row in self.db.fetch_all(
                """SELECT content_sha256 FROM validation_execution_evidence
                   WHERE execution_id=? ORDER BY created_at DESC,id DESC""",
                (execution_id,),
            )
        ]

    def _comparison_result(
        self,
        original: dict[str, Any],
        retest: dict[str, Any],
        original_sha: list[str],
        retest_sha: list[str],
    ) -> tuple[str, str, str]:
        original_matched = bool(original["result"].get("matched"))
        retest_matched = bool(retest["result"].get("matched"))
        if not original_sha or not retest_sha:
            return "INCONCLUSIVE", "Evidence is incomplete; human review is required.", "unknown"
        if original["status"] not in TERMINAL_STATUSES or retest["status"] not in TERMINAL_STATUSES:
            return "INCONCLUSIVE", "One or both executions are not terminal.", "unknown"
        if original_matched and not retest_matched:
            return (
                "REMEDIATED",
                "Original success condition no longer holds after remediation.",
                "reduced",
            )
        if original_matched and retest_matched:
            return (
                "NOT_REMEDIATED",
                "Original success condition still holds after remediation.",
                "unchanged",
            )
        if not original_matched and retest_matched:
            return (
                "REGRESSION",
                "Retest now matches a condition that was not previously present.",
                "increased",
            )
        return "INCONCLUSIVE", "No decisive before/after change was observed.", "unknown"

    def get_comparison(self, principal: Principal, retest_id: str) -> dict[str, Any]:
        retest_row = self.db.fetch_one("SELECT * FROM retest_requests WHERE id=?", (retest_id,))
        if retest_row is None:
            raise KeyError("retest request not found")
        self._get_case_row(principal, retest_row["case_id"])
        original = self.validation_execution.get(retest_row["original_execution_id"])
        retest = self.validation_execution.get(retest_row["retest_execution_id"])
        original_sha = self._execution_evidence_sha(original["id"])
        retest_sha = self._execution_evidence_sha(retest["id"])
        result, recommendation, risk_level_change = self._comparison_result(
            original,
            retest,
            original_sha,
            retest_sha,
        )
        success_diff = {
            "initial_matched": bool(original["result"].get("matched")),
            "retest_matched": bool(retest["result"].get("matched")),
            "initial_assertions": original["result"].get("assertions", {}),
            "retest_assertions": retest["result"].get("assertions", {}),
        }
        key_response_diff = {
            "initial_observed": original["result"].get("observed", {}),
            "retest_observed": retest["result"].get("observed", {}),
        }
        component_version_diff = {
            "initial_component_version": original["result"]
            .get("observed", {})
            .get("package_version"),
            "retest_component_version": retest["result"].get("observed", {}).get("package_version"),
            "template_version_changed": _bool(retest_row["template_version_changed"]),
        }
        evidence_sha = {"initial": original_sha, "retest": retest_sha}
        now = _now()
        existing = self.db.fetch_one(
            "SELECT * FROM validation_comparisons WHERE tenant_id=? AND retest_id=?",
            (retest_row["tenant_id"], retest_id),
        )
        if existing is None:
            comparison_id = str(uuid.uuid4())
            self.db.execute(
                """INSERT INTO validation_comparisons(
                   id,retest_id,case_id,finding_id,tenant_id,project_id,original_execution_id,
                   retest_execution_id,result,initial_status,retest_status,
                   success_condition_diff_json,key_response_diff_json,component_version_diff_json,
                   evidence_sha256_json,risk_level_change,residual_risk,recommendation,
                   created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    comparison_id,
                    retest_id,
                    retest_row["case_id"],
                    retest_row["finding_id"],
                    retest_row["tenant_id"],
                    retest_row["project_id"],
                    original["id"],
                    retest["id"],
                    result,
                    original["status"],
                    retest["status"],
                    _json_dumps(success_diff),
                    _json_dumps(key_response_diff),
                    _json_dumps(component_version_diff),
                    _json_dumps(evidence_sha),
                    risk_level_change,
                    None if result == "REMEDIATED" else "requires human review",
                    recommendation,
                    now,
                    now,
                ),
            )
            comparison = self.db.fetch_one(
                "SELECT * FROM validation_comparisons WHERE id=?", (comparison_id,)
            )
        else:
            self.db.execute(
                """UPDATE validation_comparisons
                   SET result=?,initial_status=?,retest_status=?,success_condition_diff_json=?,
                       key_response_diff_json=?,component_version_diff_json=?,
                       evidence_sha256_json=?,risk_level_change=?,residual_risk=?,
                       recommendation=?,updated_at=?,version=version+1
                   WHERE tenant_id=? AND retest_id=?""",
                (
                    result,
                    original["status"],
                    retest["status"],
                    _json_dumps(success_diff),
                    _json_dumps(key_response_diff),
                    _json_dumps(component_version_diff),
                    _json_dumps(evidence_sha),
                    risk_level_change,
                    None if result == "REMEDIATED" else "requires human review",
                    recommendation,
                    now,
                    retest_row["tenant_id"],
                    retest_id,
                ),
            )
            comparison = self.db.fetch_one(
                "SELECT * FROM validation_comparisons WHERE tenant_id=? AND retest_id=?",
                (retest_row["tenant_id"], retest_id),
            )
        if comparison is None:
            raise CaseStateError("comparison could not be generated")
        self._audit(
            principal,
            "comparison.review",
            "retest_request",
            retest_id,
            details={"result": result, "case_id": retest_row["case_id"]},
        )
        return self._comparison_row(comparison)

    def create_disposition(
        self,
        principal: Principal,
        case_id: str,
        value: CaseDispositionCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"case_id": case_id, **value.model_dump(mode="json")})
        with self._write_lock:
            existing = self._idempotent_response(
                principal, "case.disposition", idempotency_key, request_hash
            )
            if existing is not None:
                return existing
            case_row = self._get_case_row(principal, case_id)
            self._require_mutable(case_row)
            if case_row["status"] != "RETEST_PENDING":
                raise CaseStateError("case disposition requires RETEST_PENDING status")
            if value.disposition == "REMEDIATED":
                validated = self.db.fetch_one(
                    """SELECT id FROM case_findings
                       WHERE tenant_id=? AND case_id=? AND status='VALIDATED' LIMIT 1""",
                    (case_row["tenant_id"], case_id),
                )
                if validated is None:
                    raise CaseStateError("unvalidated findings cannot be marked remediated")
                comparison = self.db.fetch_one(
                    """SELECT * FROM validation_comparisons
                       WHERE tenant_id=? AND case_id=? AND result='REMEDIATED'
                       ORDER BY created_at DESC LIMIT 1""",
                    (case_row["tenant_id"], case_id),
                )
                if comparison is None:
                    raise CaseStateError("remediated disposition requires a remediated comparison")
            policy_decision = self._enforce_policy(
                principal,
                "case.disposition",
                "vulnerability_case",
                case_id,
                metadata={"disposition": value.disposition},
            )
            disposition_id = str(uuid.uuid4())
            now = _now()
            with self.db.transaction() as connection:
                connection.execute(
                    """INSERT INTO case_dispositions(
                       id,case_id,tenant_id,project_id,disposition,reason,residual_risk,
                       human_confirmed,decided_by,decided_at,created_at,updated_at,version
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                    (
                        disposition_id,
                        case_id,
                        case_row["tenant_id"],
                        case_row["project_id"],
                        value.disposition,
                        value.reason,
                        value.residual_risk,
                        int(value.human_confirmed),
                        principal.id,
                        now,
                        now,
                        now,
                    ),
                )
                updated = connection.execute(
                    """UPDATE vulnerability_cases
                       SET status=?,updated_by=?,updated_at=?,version=version+1
                       WHERE id=? AND tenant_id=? AND version=?""",
                    (
                        value.disposition,
                        principal.id,
                        now,
                        case_id,
                        case_row["tenant_id"],
                        value.expected_version,
                    ),
                ).rowcount
            if updated != 1:
                raise CaseStateError("case optimistic lock failed")
            response = self.get_disposition(principal, disposition_id)
            self._store_idempotency(
                principal,
                "case.disposition",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="case_disposition",
                resource_id=disposition_id,
            )
            self._audit(
                principal,
                "case.disposition",
                "vulnerability_case",
                case_id,
                details={
                    "disposition": value.disposition,
                    "policy_decision_id": policy_decision["id"],
                },
            )
            return response

    def get_disposition(self, principal: Principal, disposition_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM case_dispositions WHERE id=?", (disposition_id,))
        if row is None:
            raise KeyError("case disposition not found")
        self._get_case_row(principal, row["case_id"])
        return self._disposition_row(row)

    def close_case(
        self,
        principal: Principal,
        case_id: str,
        *,
        expected_version: int,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"case_id": case_id, "expected_version": expected_version})
        with self._write_lock:
            existing = self._idempotent_response(
                principal, "case.close", idempotency_key, request_hash
            )
            if existing is not None:
                return existing
            case_row = self._get_case_row(principal, case_id)
            if case_row["status"] == "CLOSED":
                response = self._case_row(case_row)
            else:
                if case_row["status"] not in CASE_TERMINAL_STATUSES:
                    raise CaseStateError("only dispositioned cases can be closed")
                self._enforce_policy(principal, "case.close", "vulnerability_case", case_id)
                response = self._transition_case(
                    principal,
                    case_row,
                    "CLOSED",
                    expected_version=expected_version,
                    details={"closed_by": principal.id},
                )
            self._store_idempotency(
                principal,
                "case.close",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="vulnerability_case",
                resource_id=case_id,
            )
            return response

    def generate_report(
        self,
        principal: Principal,
        case_id: str,
        value: CaseReportCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest({"case_id": case_id, **value.model_dump(mode="json")})
        with self._write_lock:
            existing = self._idempotent_response(
                principal, "report.generate", idempotency_key, request_hash
            )
            if existing is not None:
                return existing
            case_row = self._get_case_row(principal, case_id)
            policy_decision = self._enforce_policy(
                principal,
                "report.generate",
                "vulnerability_case",
                case_id,
            )
            detail = self.get_case_detail(principal, case_id)
            report_id = str(uuid.uuid4())
            now = _now()
            title = value.title or f"Vulnerability case report: {case_row['title']}"
            report = {
                "case": detail["case"],
                "finding_count": len(detail["findings"]),
                "proposal_count": len(detail["remediation_proposals"]),
                "implementation_count": len(detail["remediation_implementations"]),
                "retest_count": len(detail["retests"]),
                "comparison_results": [item["result"] for item in detail["comparisons"]],
                "latest_disposition": detail["dispositions"][0] if detail["dispositions"] else None,
                "generated_at": now,
                "policy_decision_id": policy_decision["id"],
            }
            self.db.execute(
                """INSERT INTO case_reports(
                   id,case_id,tenant_id,project_id,title,report_json,generated_by,
                   generated_at,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    report_id,
                    case_id,
                    case_row["tenant_id"],
                    case_row["project_id"],
                    title,
                    _json_dumps(report),
                    principal.id,
                    now,
                    now,
                    now,
                ),
            )
            response = self.get_report(principal, report_id)
            self._store_idempotency(
                principal,
                "report.generate",
                idempotency_key or "",
                request_hash,
                response,
                resource_type="case_report",
                resource_id=report_id,
            )
            self._audit(
                principal,
                "report.generate",
                "vulnerability_case",
                case_id,
                details={"report_id": report_id, "policy_decision_id": policy_decision["id"]},
            )
            return response

    def get_report(self, principal: Principal, report_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM case_reports WHERE id=?", (report_id,))
        if row is None:
            raise KeyError("case report not found")
        self._get_case_row(principal, row["case_id"])
        return self._report_row(row)
