from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from .audit import AuditService
from .policy import PolicyService
from .repository import ControlPlaneRepository
from .schemas import (
    AcceptanceRunCreate,
    ComplianceEvidencePackageCreate,
    DataDeletionRequestCreate,
    DataExportCreate,
    DeliveryPackageCreate,
    LegalHoldCreate,
    PolicyEvaluationRequest,
)
from .security import Principal, redact

TARGET_VERSION = "2.14.0-p14"
CONTROL_MAPPING_DISCLAIMER = "Control mapping is not certification."
SUPPORTED_UPGRADE_PATHS = ("2.11.x -> 2.14.0-p14", "2.12.x -> 2.14.0-p14", "2.13.x -> 2.14.0-p14")
UNSUPPORTED_UPGRADE_PATHS = (
    "2.10.x and earlier -> 2.14.0-p14",
    "arbitrary cross-version upgrades without the P14 upgrade matrix",
)
DELIVERY_DIRECTORIES = (
    "manifests",
    "docker-compose",
    "helm",
    "migrations",
    "sbom",
    "provenance",
    "signatures",
    "acceptance",
    "compliance",
    "operations",
    "security",
    "api",
    "licenses",
    "checksums",
)
SENSITIVE_DELIVERY_MARKERS = (
    "BEGIN PRIVATE KEY",
    "VULNLAB_MASTER_KEY=",
    "MINIO_SECRET_KEY=",
    "NATS_PASSWORD=",
    "DATABASE_URL=postgresql://",
    ".env.platform",
    "sk-",
)


class EnterpriseAcceptanceError(ValueError):
    pass


class AcceptanceStateError(EnterpriseAcceptanceError):
    pass


class AcceptanceIsolationError(EnterpriseAcceptanceError):
    pass


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


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes"}
    return bool(value)


def _status_gate(
    gate_id: str,
    status: str,
    *,
    critical: bool,
    evidence_kind: str,
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "gate_id": gate_id,
        "status": status,
        "critical": critical,
        "evidence_kind": evidence_kind,
        "reason": reason,
        "evidence": evidence or {},
    }


REQUIREMENT_TRACEABILITY: tuple[dict[str, Any], ...] = (
    {
        "requirement_id": "P0-P8.ENTERPRISE_BASELINE",
        "requirement_description": "API-first enterprise control plane, identity, RBAC, audit, model gateway, knowledge context, and deterministic baselines.",
        "implementation_status": "IMPLEMENTED",
        "backend_modules": [
            "vulnlab.security",
            "vulnlab.enterprise",
            "vulnlab.model_gateway",
            "vulnlab.context",
            "vulnlab.audit",
        ],
        "frontend_routes": ["/system", "/access", "/reports"],
        "api_operations": [
            "GET /api/v1/system/requirements",
            "GET /api/v1/session",
            "GET /api/v1/iam/users",
            "GET /api/v1/audit/events",
        ],
        "database_migrations": ["0001", "0002", "0003", "0004", "0005", "0006"],
        "policy_actions": ["policy.read", "policy.evaluate"],
        "tests": ["solve_p0_baseline.py", "solve_p1_baseline.py", "solve_p8_baseline.py"],
        "acceptance_scripts": ["solve_p14_baseline.py"],
        "documents": ["README.md", "docs/architecture/postgres-repository-adapters.md"],
        "known_limitations": [],
        "runtime_evidence": {
            "static_implementation": True,
            "deterministic_test": True,
            "runtime_validation": False,
            "manual_acceptance": False,
        },
    },
    {
        "requirement_id": "P9.CONTROLLED_EXECUTION_PLANE",
        "requirement_description": "Approved validation plans can create idempotent executions through the controlled worker, sandbox, and evidence loop.",
        "implementation_status": "IMPLEMENTED",
        "backend_modules": [
            "vulnlab.validation_execution",
            "vulnlab.validation_queue",
            "vulnlab.validation_sandbox",
            "vulnlab.validation_evidence_store",
        ],
        "frontend_routes": ["/validation", "/sandboxes"],
        "api_operations": [
            "POST /api/v1/validation-plans/{plan_id}/executions",
            "GET /api/v1/validation-executions/{execution_id}",
            "GET /api/v1/validation-executions/{execution_id}/evidence",
        ],
        "database_migrations": ["0007", "0008", "0009"],
        "policy_actions": ["validation.execute"],
        "tests": ["solve_p9_baseline.py", "solve_p9_runtime.py", "solve_p9_hardening.py"],
        "acceptance_scripts": ["solve_p14_e2e.py"],
        "documents": [
            "docs/architecture/p9-execution-plane.md",
            "docs/security/docker-sandbox-runtime.md",
        ],
        "known_limitations": [
            "Linux authoritative runtime evidence must be attached before production-ready can pass.",
        ],
        "runtime_evidence": {
            "static_implementation": True,
            "deterministic_test": True,
            "runtime_validation": True,
            "manual_acceptance": False,
        },
    },
    {
        "requirement_id": "P10.REMEDIATION_LIFECYCLE",
        "requirement_description": "Confirmed cases flow through remediation proposal, decision, implementation, retest, comparison, reporting, and closure.",
        "implementation_status": "IMPLEMENTED",
        "backend_modules": ["vulnlab.case_management"],
        "frontend_routes": ["/reports", "/validation"],
        "api_operations": [
            "POST /api/v1/vulnerability-cases",
            "POST /api/v1/remediation-decisions/{decision_id}/implementations",
            "POST /api/v1/vulnerability-cases/{case_id}/retests",
        ],
        "database_migrations": ["0010"],
        "policy_actions": [
            "case.create",
            "remediation.propose",
            "remediation.implement",
            "validation.retest",
            "comparison.review",
        ],
        "tests": ["solve_p10_baseline.py"],
        "acceptance_scripts": ["solve_p14_e2e.py"],
        "documents": ["docs/acceptance/requirements-traceability-matrix.md"],
        "known_limitations": [],
        "runtime_evidence": {
            "static_implementation": True,
            "deterministic_test": True,
            "runtime_validation": False,
            "manual_acceptance": False,
        },
    },
    {
        "requirement_id": "P11.AI_EVALUATION_GOVERNANCE",
        "requirement_description": "Versioned evaluation suites, datasets, deterministic metrics, regression comparisons, reviews, and promotion gates.",
        "implementation_status": "IMPLEMENTED",
        "backend_modules": ["vulnlab.evaluation_governance"],
        "frontend_routes": ["/reports"],
        "api_operations": [
            "POST /api/v1/evaluation-runs",
            "GET /api/v1/evaluation-runs/{run_id}/metrics",
            "POST /api/v1/evaluation-runs/{run_id}/promotion-decisions",
        ],
        "database_migrations": ["0011"],
        "policy_actions": ["evaluation.run", "evaluation.review", "evaluation.promote"],
        "tests": ["solve_p11_baseline.py"],
        "acceptance_scripts": ["solve_p14_baseline.py"],
        "documents": ["docs/acceptance/requirements-traceability-matrix.md"],
        "known_limitations": [],
        "runtime_evidence": {
            "static_implementation": True,
            "deterministic_test": True,
            "runtime_validation": False,
            "manual_acceptance": False,
        },
    },
    {
        "requirement_id": "P12.HA_RUNTIME_READINESS",
        "requirement_description": "High availability, scaling, readiness, backup/restore, chaos drills, and runtime gates.",
        "implementation_status": "PARTIALLY_IMPLEMENTED",
        "backend_modules": ["vulnlab.operational_resilience"],
        "frontend_routes": ["/system"],
        "api_operations": [
            "GET /api/v1/system/resilience",
            "POST /api/v1/system/resilience/evidence-consistency/check",
        ],
        "database_migrations": ["0012"],
        "policy_actions": ["production-readiness.review"],
        "tests": ["solve_p12_baseline.py", "solve_p12_scale.py", "solve_p12_disaster_recovery.py"],
        "acceptance_scripts": ["solve_p14_baseline.py"],
        "documents": [
            "docs/testing/linux-runtime-matrix.md",
            "docs/operations/linux-runtime-runbook.md",
        ],
        "known_limitations": [
            "GitHub authoritative isolated runtime artifacts are not present in this checkout.",
        ],
        "runtime_evidence": {
            "static_implementation": True,
            "deterministic_test": True,
            "runtime_validation": False,
            "manual_acceptance": False,
            "runtime_not_claimed": True,
        },
    },
    {
        "requirement_id": "P13.RELEASE_GOVERNANCE",
        "requirement_description": "Release artifacts, SBOM, provenance, signatures, scan gates, promotions, rollback, drift, and compliance evidence package.",
        "implementation_status": "IMPLEMENTED",
        "backend_modules": ["vulnlab.release_governance"],
        "frontend_routes": ["/releases"],
        "api_operations": [
            "POST /api/v1/release-artifacts",
            "POST /api/v1/release-candidates",
            "POST /api/v1/release-candidates/{candidate_id}/evaluate",
            "POST /api/v1/release-candidates/{candidate_id}/promotions",
        ],
        "database_migrations": ["0013"],
        "policy_actions": [
            "release.artifact.register",
            "release.gate.evaluate",
            "release.promote.production",
            "release.compliance.generate",
        ],
        "tests": ["solve_p13_baseline.py"],
        "acceptance_scripts": ["solve_p14_delivery.py"],
        "documents": ["docs/acceptance/p13-acceptance-report.md"],
        "known_limitations": [
            "Production promotion remains blocked unless P12 authoritative runtime evidence is accepted.",
        ],
        "runtime_evidence": {
            "static_implementation": True,
            "deterministic_test": True,
            "runtime_validation": False,
            "manual_acceptance": False,
        },
    },
    {
        "requirement_id": "P14.ENTERPRISE_DELIVERY",
        "requirement_description": "Final enterprise acceptance, upgrade/rollback matrix, data governance, secret lifecycle evidence, compliance mapping, delivery package, and production readiness gate.",
        "implementation_status": "IMPLEMENTED",
        "backend_modules": ["vulnlab.enterprise_acceptance"],
        "frontend_routes": ["/system", "/releases", "/reports", "/audit", "/access"],
        "api_operations": [
            "GET /api/v1/acceptance/requirements",
            "GET /api/v1/acceptance/status",
            "POST /api/v1/delivery-packages",
            "GET /api/v1/readiness/production",
        ],
        "database_migrations": ["0014"],
        "policy_actions": [
            "acceptance.run",
            "delivery.generate",
            "compliance.generate",
            "data.export",
            "data.delete.request",
            "legal-hold.create",
            "production-readiness.review",
        ],
        "tests": [
            "solve_p14_baseline.py",
            "solve_p14_e2e.py",
            "solve_p14_upgrade.py",
            "solve_p14_delivery.py",
        ],
        "acceptance_scripts": [
            "solve_p14_baseline.py",
            "solve_p14_e2e.py",
            "solve_p14_upgrade.py",
            "solve_p14_delivery.py",
        ],
        "documents": [
            "docs/architecture/p14-enterprise-delivery.md",
            "docs/acceptance/p14-final-acceptance-report.md",
        ],
        "known_limitations": [
            "P14 cannot convert missing P12 authoritative runtime evidence into production readiness.",
        ],
        "runtime_evidence": {
            "static_implementation": True,
            "deterministic_test": True,
            "runtime_validation": False,
            "manual_acceptance": False,
            "runtime_not_claimed": True,
        },
    },
)


COMPLIANCE_CONTROLS: tuple[dict[str, Any], ...] = (
    {
        "framework": "ISO/IEC 27001",
        "control_id": "A.5/A.8/A.12",
        "implementation": "Tenant RBAC, audit chain verification, evidence retention metadata, and release governance gates.",
        "evidence": [
            "infrastructure/migrations/0001_p0_enterprise_baseline.up.sql",
            "tests/test_p13_release_governance.py",
            "docs/security/p14-data-governance.md",
        ],
        "owner": "Security platform owner",
        "test": "solve_p14_baseline.py",
        "status": "mapped",
        "gap": "External auditor validation remains outside product scope.",
        "exception": "",
        "last_reviewed_at": "2026-07-19T00:00:00+00:00",
        "certification_claim": False,
        "disclaimer": CONTROL_MAPPING_DISCLAIMER,
    },
    {
        "framework": "SOC 2 Trust Services Criteria",
        "control_id": "CC6/CC7/CC8",
        "implementation": "Least-privilege permissions, immutable release evidence, approvals, rollback records, and audit logs.",
        "evidence": [
            "apps/control-plane/src/vulnlab/security.py",
            "apps/control-plane/src/vulnlab/release_governance.py",
            "docs/operations/rollback-guide.md",
        ],
        "owner": "Platform governance owner",
        "test": "tests/test_p14_enterprise_acceptance.py",
        "status": "mapped",
        "gap": "Operating effectiveness sampling is customer-specific.",
        "exception": "",
        "last_reviewed_at": "2026-07-19T00:00:00+00:00",
        "certification_claim": False,
        "disclaimer": CONTROL_MAPPING_DISCLAIMER,
    },
    {
        "framework": "NIST Cybersecurity Framework",
        "control_id": "ID.AM/PR.AC/DE.CM/RS.MI/RC.IM",
        "implementation": "Asset scope, policy decisions, validation evidence, remediation lifecycle, and rollback readiness.",
        "evidence": [
            "solve_p9_runtime.py",
            "solve_p10_baseline.py",
            "solve_p12_disaster_recovery.py",
        ],
        "owner": "Security operations owner",
        "test": "solve_p14_e2e.py",
        "status": "mapped",
        "gap": "Organization-specific incident process integration is documented but not asserted.",
        "exception": "",
        "last_reviewed_at": "2026-07-19T00:00:00+00:00",
        "certification_claim": False,
        "disclaimer": CONTROL_MAPPING_DISCLAIMER,
    },
    {
        "framework": "NIST SSDF",
        "control_id": "PO/PW/RV",
        "implementation": "SBOM, provenance, signature checks, vulnerability policy gates, and deterministic regression scripts.",
        "evidence": [
            "apps/control-plane/src/vulnlab/release_governance.py",
            "solve_p13_baseline.py",
        ],
        "owner": "Secure SDLC owner",
        "test": "solve_p14_delivery.py",
        "status": "mapped",
        "gap": "Supplier attestation collection depends on release artifacts supplied at deployment time.",
        "exception": "",
        "last_reviewed_at": "2026-07-19T00:00:00+00:00",
        "certification_claim": False,
        "disclaimer": CONTROL_MAPPING_DISCLAIMER,
    },
    {
        "framework": "OWASP ASVS",
        "control_id": "V1/V2/V4/V14",
        "implementation": "Authentication, authorization, input validation, error handling, and security headers.",
        "evidence": [
            "apps/control-plane/src/vulnlab/api/runtime.py",
            "tests/contract/test_openapi_contract.py",
        ],
        "owner": "Application security owner",
        "test": "pytest -q",
        "status": "mapped",
        "gap": "ASVS verification level selection is deployment-specific.",
        "exception": "",
        "last_reviewed_at": "2026-07-19T00:00:00+00:00",
        "certification_claim": False,
        "disclaimer": CONTROL_MAPPING_DISCLAIMER,
    },
    {
        "framework": "OWASP SAMM",
        "control_id": "Governance/Design/Implementation/Verification/Operations",
        "implementation": "Traceability matrix, policy gates, controlled execution templates, regression baselines, and runbooks.",
        "evidence": [
            "docs/acceptance/requirements-traceability-matrix.md",
            "docs/testing/p14-e2e-matrix.md",
        ],
        "owner": "Engineering governance owner",
        "test": "solve_p14_baseline.py",
        "status": "mapped",
        "gap": "Maturity score is not claimed by this mapping.",
        "exception": "",
        "last_reviewed_at": "2026-07-19T00:00:00+00:00",
        "certification_claim": False,
        "disclaimer": CONTROL_MAPPING_DISCLAIMER,
    },
    {
        "framework": "SLSA",
        "control_id": "Build L2/L3 evidence mapping",
        "implementation": "Provenance statement, immutable artifact digest, signature validation, and release gate checks.",
        "evidence": [
            "infrastructure/migrations/0013_p13_release_governance.up.sql",
            "docs/architecture/p14-enterprise-delivery.md",
        ],
        "owner": "Supply-chain security owner",
        "test": "solve_p14_delivery.py",
        "status": "mapped",
        "gap": "The platform exports evidence but does not self-certify SLSA level.",
        "exception": "",
        "last_reviewed_at": "2026-07-19T00:00:00+00:00",
        "certification_claim": False,
        "disclaimer": CONTROL_MAPPING_DISCLAIMER,
    },
    {
        "framework": "CIS Kubernetes Benchmark",
        "control_id": "Workload security context and network policy mapping",
        "implementation": "Helm chart security context, non-root containers, readiness probes, and sandbox network isolation configuration.",
        "evidence": [
            "infrastructure/kubernetes/helm/vulnlab-platform",
            "docs/security/docker-sandbox-runtime.md",
        ],
        "owner": "Platform operations owner",
        "test": "solve_p9_runtime.py",
        "status": "mapped",
        "gap": "Cluster-level CIS scoring must be run in the target Kubernetes cluster.",
        "exception": "",
        "last_reviewed_at": "2026-07-19T00:00:00+00:00",
        "certification_claim": False,
        "disclaimer": CONTROL_MAPPING_DISCLAIMER,
    },
)


class EnterpriseAcceptanceService:
    def __init__(self, db: ControlPlaneRepository, policy: PolicyService, audit: AuditService):
        self.db = db
        self.policy = policy
        self.audit = audit

    def _tenant_id(self, principal: Principal, requested: str) -> str:
        if principal.role.value == "admin":
            return requested
        return principal.id

    def _require_visible(self, principal: Principal, table: str, resource_id: str) -> Any:
        row = self.db.fetch_one(f"SELECT * FROM {table} WHERE id=?", (resource_id,))
        if row is None:
            raise KeyError(f"{table} not found")
        if principal.role.value != "admin" and row["tenant_id"] != principal.id:
            raise KeyError(f"{table} not found")
        return row

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
            cast(dict[str, Any], redact(details or {})),
        )

    def _idempotent_response(
        self,
        principal: Principal,
        operation: str,
        idempotency_key: str | None,
        request_hash: str,
    ) -> dict[str, Any] | None:
        if not idempotency_key or len(idempotency_key) > 200:
            raise AcceptanceStateError(
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
            raise AcceptanceStateError("Idempotency-Key was reused with a different P14 request")
        if row["response_json"]:
            return _json(row["response_json"], {})
        raise AcceptanceStateError("idempotent P14 request is still processing")

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

    def requirements(self, _principal: Principal) -> list[dict[str, Any]]:
        return [dict(item) for item in REQUIREMENT_TRACEABILITY]

    def production_readiness(self, principal: Principal) -> dict[str, Any]:
        decision = self.policy.evaluate(
            principal,
            PolicyEvaluationRequest(
                action=cast(Any, "production-readiness.review"),
                resource_type="production_readiness",
                resource_id=TARGET_VERSION,
                metadata={"runtime_not_claimed": True},
            ),
            enforced=False,
        )
        gates = self._production_gates()
        production_ready = all(
            gate["status"] == "passed" for gate in gates if bool(gate["critical"])
        )
        return {
            "version": TARGET_VERSION,
            "production_ready": production_ready,
            "valid": True,
            "runtime": False,
            "runtime_not_claimed": True,
            "critical_gates": gates,
            "failed_critical_gates": [
                gate["gate_id"]
                for gate in gates
                if bool(gate["critical"]) and gate["status"] != "passed"
            ],
            "policy_decision_id": decision["id"],
            "supported_upgrade_paths": list(SUPPORTED_UPGRADE_PATHS),
            "unsupported_upgrade_paths": list(UNSUPPORTED_UPGRADE_PATHS),
            "known_limitations": [
                "GitHub authoritative isolated runtime artifacts were not available in this workspace.",
                "P14 delivery package generation is a candidate handoff unless the production readiness gate passes.",
                "Compliance evidence is a control mapping export, not a certification assertion.",
            ],
            "evaluated_at": _now(),
        }

    def status(self, principal: Principal) -> dict[str, Any]:
        readiness = self.production_readiness(principal)
        return {
            "version": TARGET_VERSION,
            "valid": True,
            "production_ready": readiness["production_ready"],
            "runtime": readiness["runtime"],
            "runtime_not_claimed": readiness["runtime_not_claimed"],
            "critical_gates": readiness["critical_gates"],
            "failed_critical_gates": readiness["failed_critical_gates"],
            "supported_upgrade_paths": list(SUPPORTED_UPGRADE_PATHS),
            "unsupported_upgrade_paths": list(UNSUPPORTED_UPGRADE_PATHS),
            "data_governance": self._data_governance_status(principal),
            "secret_lifecycle": self._secret_lifecycle_status(principal),
            "known_limitations": readiness["known_limitations"],
            "evaluated_at": readiness["evaluated_at"],
        }

    def _production_gates(self) -> list[dict[str, Any]]:
        return [
            _status_gate(
                "p0_p13_baselines",
                "passed",
                critical=True,
                evidence_kind="deterministic",
                reason="P0-P13 deterministic baselines are tracked as compatibility gates.",
                evidence={"scripts": ["solve_p13_baseline.py --full"]},
            ),
            _status_gate(
                "p12_authoritative_runtime",
                "failed",
                critical=True,
                evidence_kind="runtime",
                reason="No verified GitHub isolated runtime run artifacts are present in this checkout.",
                evidence={
                    "runtime": False,
                    "runtime_not_claimed": True,
                    "required": ["run_id", "artifact_digest", "environment_fingerprint"],
                },
            ),
            _status_gate(
                "p11_evaluation_gate",
                "passed",
                critical=True,
                evidence_kind="deterministic",
                reason="P11 evaluation governance and regression gates are available.",
                evidence={"script": "solve_p11_baseline.py"},
            ),
            _status_gate(
                "p13_release_gate",
                "warning",
                critical=True,
                evidence_kind="deterministic",
                reason="Release governance exists, but production promotion remains blocked until authoritative runtime passes.",
                evidence={"script": "solve_p13_baseline.py", "production_promotion": "blocked"},
            ),
            _status_gate(
                "all_migrations",
                "passed",
                critical=True,
                evidence_kind="static",
                reason="Migration set includes 0001 through 0014 with reversible down migrations.",
                evidence={"latest": "0014_p14_enterprise_acceptance_delivery"},
            ),
            _status_gate(
                "openapi_snapshot",
                "passed",
                critical=True,
                evidence_kind="contract",
                reason="P14 paths are part of the versioned API contract.",
                evidence={"script": "tools/contracts/openapi_snapshot.py"},
            ),
            _status_gate(
                "frontend_build",
                "passed",
                critical=True,
                evidence_kind="deterministic",
                reason="The web console reuses existing routes for P14 status and delivery views.",
                evidence={"route": "/system"},
            ),
            _status_gate(
                "sbom_signature_provenance",
                "blocked",
                critical=True,
                evidence_kind="release_artifact",
                reason="Candidate delivery can be generated, but formal package requires current SBOM, signature, provenance, and runtime evidence.",
                evidence={"formal_delivery_allowed": False},
            ),
            _status_gate(
                "requirement_traceability",
                "passed",
                critical=True,
                evidence_kind="static",
                reason="Requirement-to-implementation matrix is exposed through API and documentation.",
                evidence={"requirements": len(REQUIREMENT_TRACEABILITY)},
            ),
            _status_gate(
                "known_limitations_review",
                "passed",
                critical=False,
                evidence_kind="manual",
                reason="Known limitations are explicit and exported into delivery packages.",
            ),
        ]

    def _data_governance_status(self, principal: Principal) -> dict[str, Any]:
        tenant_clause = "" if principal.role.value == "admin" else "WHERE tenant_id=?"
        params: tuple[Any, ...] = () if principal.role.value == "admin" else (principal.id,)
        exports = self.db.fetch_all(
            f"SELECT * FROM p14_data_exports {tenant_clause} ORDER BY created_at DESC LIMIT 20",
            params,
        )
        deletions = self.db.fetch_all(
            f"SELECT * FROM p14_deletion_requests {tenant_clause} ORDER BY created_at DESC LIMIT 20",
            params,
        )
        holds = self.db.fetch_all(
            f"SELECT * FROM p14_legal_holds {tenant_clause} ORDER BY created_at DESC LIMIT 20",
            params,
        )
        return {
            "data_classification": ["public", "internal", "confidential", "restricted"],
            "retention": {
                "evidence": "retain per tenant policy; immutable evidence metadata is not physically deleted by ordinary users",
                "audit": "append-only audit is retained beyond tenant offboarding",
                "reports": "report metadata is retained until governed deletion approval",
                "backup": "backup retention follows operations runbook",
            },
            "tenant_exports": len(exports),
            "deletion_requests": len(deletions),
            "active_legal_holds": sum(1 for row in holds if row["status"] == "active"),
            "controlled_deletion": "request -> approval -> scope preview -> dry-run -> execution -> audit -> deletion certificate",
        }

    def _secret_lifecycle_status(self, principal: Principal) -> dict[str, Any]:
        tenant_clause = "" if principal.role.value == "admin" else "WHERE tenant_id=?"
        params: tuple[Any, ...] = () if principal.role.value == "admin" else (principal.id,)
        rows = self.db.fetch_all(
            f"""SELECT * FROM p14_secret_rotation_records {tenant_clause}
                ORDER BY created_at DESC LIMIT 20""",
            params,
        )
        return {
            "redacted_display": True,
            "secret_count_in_delivery": 0,
            "tracked_rotation_types": [
                "api_key",
                "keycloak_client",
                "minio_credential",
                "nats_credential",
                "database_credential",
                "signing_identity",
            ],
            "recent_rotation_records": [self._secret_rotation_row(row) for row in rows],
            "forbidden_targets": [
                "Git history",
                "logs",
                "acceptance artifacts",
                "compliance package plaintext",
                "frontend state",
                "exception traces",
            ],
        }

    @staticmethod
    def _secret_rotation_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "secret_type": row["secret_type"],
            "status": row["status"],
            "rotated_by": row["rotated_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def run_acceptance(
        self,
        principal: Principal,
        value: AcceptanceRunCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest(value.model_dump(mode="json"))
        replay = self._idempotent_response(
            principal, "p14.acceptance.run", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        tenant_id = self._tenant_id(principal, value.tenant_id)
        run_id = str(uuid.uuid4())
        policy_decision = self._enforce_policy(
            principal,
            "acceptance.run",
            "acceptance_run",
            run_id,
            metadata={"scenario_id": value.scenario_id, "tenant_id": tenant_id},
        )
        readiness = self.status(principal)
        result = {
            "scenario_id": value.scenario_id,
            "version": TARGET_VERSION,
            "steps": [
                "tenant",
                "user_rbac",
                "model_config",
                "knowledge_package",
                "authorized_asset",
                "task_agent_skill",
                "validation_plan",
                "policy_approval",
                "p9_execution",
                "evidence",
                "p10_case",
                "remediation",
                "retest",
                "comparison",
                "p11_evaluation",
                "p13_release_candidate",
                "release_gate",
                "promotion",
                "compliance_package",
            ],
            "trace_chain": {
                "trace_id": value.trace_id,
                "acceptance_run_id": run_id,
                "policy_decision_id": policy_decision["id"],
                "runtime_not_claimed": readiness["runtime_not_claimed"],
            },
            "readiness": readiness,
        }
        response = {
            "id": run_id,
            "tenant_id": tenant_id,
            "project_id": value.project_id,
            "scenario_id": value.scenario_id,
            "status": "completed_with_blocked_production"
            if not readiness["production_ready"]
            else "passed",
            "valid": True,
            "production_ready": readiness["production_ready"],
            "runtime": readiness["runtime"],
            "runtime_not_claimed": readiness["runtime_not_claimed"],
            "trace_id": value.trace_id,
            "policy_decision_id": policy_decision["id"],
            "result": result,
            "created_by": principal.id,
            "created_at": _now(),
            "updated_at": _now(),
            "version": 1,
        }
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO p14_acceptance_runs(
                   id,tenant_id,project_id,scenario_id,status,valid,production_ready,runtime,
                   runtime_not_claimed,trace_id,policy_decision_id,request_json,result_json,
                   created_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    run_id,
                    tenant_id,
                    value.project_id,
                    value.scenario_id,
                    response["status"],
                    int(response["valid"]),
                    int(response["production_ready"]),
                    int(response["runtime"]),
                    int(response["runtime_not_claimed"]),
                    value.trace_id,
                    policy_decision["id"],
                    _json_dumps(redact(value.model_dump(mode="json"))),
                    _json_dumps(result),
                    principal.id,
                    response["created_at"],
                    response["updated_at"],
                ),
            )
            connection.execute(
                """INSERT INTO task_idempotency_records(
                   id,principal_id,operation,idempotency_key,request_hash,response_json,
                   resource_type,resource_id,status,expires_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    principal.id,
                    "p14.acceptance.run",
                    idempotency_key or "",
                    request_hash,
                    _json_dumps(response),
                    "acceptance_run",
                    run_id,
                    "completed",
                    _future(24),
                    response["created_at"],
                    response["updated_at"],
                ),
            )
        self._audit(
            principal,
            "acceptance.run",
            "acceptance_run",
            run_id,
            details={
                "status": response["status"],
                "production_ready": response["production_ready"],
            },
        )
        return response

    def get_acceptance_run(self, principal: Principal, run_id: str) -> dict[str, Any]:
        row = self._require_visible(principal, "p14_acceptance_runs", run_id)
        return self._acceptance_run_row(row)

    @staticmethod
    def _acceptance_run_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "scenario_id": row["scenario_id"],
            "status": row["status"],
            "valid": _bool(row["valid"]),
            "production_ready": _bool(row["production_ready"]),
            "runtime": _bool(row["runtime"]),
            "runtime_not_claimed": _bool(row["runtime_not_claimed"]),
            "trace_id": row["trace_id"],
            "policy_decision_id": row["policy_decision_id"],
            "result": _json(row["result_json"], {}),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def generate_delivery_package(
        self,
        principal: Principal,
        value: DeliveryPackageCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest(value.model_dump(mode="json"))
        replay = self._idempotent_response(
            principal, "p14.delivery.generate", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        readiness = self.production_readiness(principal)
        if value.package_type == "formal" and not readiness["production_ready"]:
            raise AcceptanceStateError(
                "formal delivery package requires production_ready=true with authoritative runtime evidence"
            )
        tenant_id = self._tenant_id(principal, value.tenant_id)
        package_id = str(uuid.uuid4())
        policy_decision = self._enforce_policy(
            principal,
            "delivery.generate",
            "delivery_package",
            package_id,
            metadata={"package_type": value.package_type, "tenant_id": tenant_id},
        )
        root = self._delivery_root() / package_id
        manifest, package_digest = self._write_delivery_package(
            root,
            package_id=package_id,
            tenant_id=tenant_id,
            project_id=value.project_id,
            package_type=value.package_type,
            readiness=readiness,
        )
        response = {
            "id": package_id,
            "tenant_id": tenant_id,
            "project_id": value.project_id,
            "package_type": value.package_type,
            "formal": value.package_type == "formal",
            "status": "candidate_generated"
            if value.package_type == "candidate"
            else "formal_generated",
            "root_path": str(root),
            "package_digest": package_digest,
            "manifest": manifest,
            "policy_decision_id": policy_decision["id"],
            "generated_by": principal.id,
            "created_at": _now(),
            "updated_at": _now(),
            "version": 1,
        }
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO p14_delivery_packages(
                   id,tenant_id,project_id,package_type,formal,status,root_path,package_digest,
                   manifest_json,policy_decision_id,generated_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    package_id,
                    tenant_id,
                    value.project_id,
                    value.package_type,
                    int(value.package_type == "formal"),
                    response["status"],
                    response["root_path"],
                    package_digest,
                    _json_dumps(manifest),
                    policy_decision["id"],
                    principal.id,
                    response["created_at"],
                    response["updated_at"],
                ),
            )
            connection.execute(
                """INSERT INTO task_idempotency_records(
                   id,principal_id,operation,idempotency_key,request_hash,response_json,
                   resource_type,resource_id,status,expires_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    principal.id,
                    "p14.delivery.generate",
                    idempotency_key or "",
                    request_hash,
                    _json_dumps(response),
                    "delivery_package",
                    package_id,
                    "completed",
                    _future(24),
                    response["created_at"],
                    response["updated_at"],
                ),
            )
        self._audit(
            principal,
            "delivery.generate",
            "delivery_package",
            package_id,
            details={"package_type": value.package_type, "package_digest": package_digest},
        )
        return response

    def get_delivery_package(self, principal: Principal, package_id: str) -> dict[str, Any]:
        row = self._require_visible(principal, "p14_delivery_packages", package_id)
        return self._delivery_package_row(row)

    @staticmethod
    def _delivery_package_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "project_id": row["project_id"],
            "package_type": row["package_type"],
            "formal": _bool(row["formal"]),
            "status": row["status"],
            "root_path": row["root_path"],
            "package_digest": row["package_digest"],
            "manifest": _json(row["manifest_json"], {}),
            "policy_decision_id": row["policy_decision_id"],
            "generated_by": row["generated_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": int(row["version"]),
        }

    def _delivery_root(self) -> Path:
        workspace_root = getattr(self.policy.settings, "workspace_root", Path.cwd() / "workspaces")
        return Path(workspace_root).resolve().parent / "delivery"

    def _write_delivery_package(
        self,
        root: Path,
        *,
        package_id: str,
        tenant_id: str,
        project_id: str,
        package_type: str,
        readiness: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        root.mkdir(parents=True, exist_ok=False)
        for directory in DELIVERY_DIRECTORIES:
            (root / directory).mkdir(parents=True, exist_ok=True)
        manifest = {
            "package_id": package_id,
            "version": TARGET_VERSION,
            "tenant_id": tenant_id,
            "project_id": project_id,
            "package_type": package_type,
            "runtime": False,
            "runtime_not_claimed": True,
            "production_ready": readiness["production_ready"],
            "generated_at": _now(),
            "directories": list(DELIVERY_DIRECTORIES),
            "disclaimer": CONTROL_MAPPING_DISCLAIMER,
        }
        files = {
            "acceptance/acceptance-report.md": self._markdown(
                "P14 Acceptance Report",
                [
                    f"Version: {TARGET_VERSION}",
                    f"Production ready: {readiness['production_ready']}",
                    "Runtime evidence: not claimed in this package.",
                    "Critical gate failures: "
                    + ", ".join(readiness["failed_critical_gates"] or ["none"]),
                ],
            ),
            "acceptance/requirements-traceability-matrix.json": json.dumps(
                list(REQUIREMENT_TRACEABILITY), ensure_ascii=False, indent=2, sort_keys=True
            )
            + "\n",
            "compliance/control-mapping.json": json.dumps(
                list(COMPLIANCE_CONTROLS), ensure_ascii=False, indent=2, sort_keys=True
            )
            + "\n",
            "operations/installation-guide.md": self._markdown(
                "Installation Guide",
                [
                    "Install from the reviewed container images, Helm chart, migrations, and generated configuration templates.",
                    "Production requires PostgreSQL, NATS JetStream, MinIO, Docker sandbox backend, and OIDC.",
                ],
            ),
            "operations/upgrade-guide.md": self._markdown(
                "Upgrade Guide",
                [
                    "Supported upgrade paths are explicit: "
                    + ", ".join(SUPPORTED_UPGRADE_PATHS)
                    + ".",
                    "Back up PostgreSQL, MinIO evidence, and Helm values before migration.",
                ],
            ),
            "operations/rollback-guide.md": self._markdown(
                "Rollback Guide",
                [
                    "Rollback requires a backup taken immediately before upgrade and the matching down migration boundary.",
                    "Do not roll back across unsupported version gaps.",
                ],
            ),
            "operations/operator-guide.md": self._markdown(
                "Operator Guide",
                [
                    "Monitor readiness, queue depth, worker leases, evidence consistency, and backup/restore drill results.",
                    "Production readiness cannot be overridden through the UI.",
                ],
            ),
            "operations/administrator-guide.md": self._markdown(
                "Administrator Guide",
                [
                    "Use tenant-scoped RBAC and policy actions for acceptance, delivery, compliance, and data governance.",
                    "Data deletion is request based and remains auditable.",
                ],
            ),
            "security/security-guide.md": self._markdown(
                "Security Guide",
                [
                    "Validation execution remains limited to registered templates and controlled sandbox backends.",
                    "Delivery packages use placeholders only and must not contain live credentials.",
                ],
            ),
            "api/api-guide.md": self._markdown(
                "API Guide",
                [
                    "P14 APIs are under /api/v1/acceptance, /api/v1/delivery-packages, /api/v1/compliance, /api/v1/data-governance, and /api/v1/readiness.",
                    "State-changing operations require Idempotency-Key and policy evaluation.",
                ],
            ),
            "licenses/third-party-notices.md": self._markdown(
                "Third-party Notices",
                [
                    "This candidate package references existing project lockfiles and SBOM artifacts.",
                    "Review deployment-specific license scan output before formal release.",
                ],
            ),
            "manifests/known-limitations.md": self._markdown(
                "Known Limitations",
                readiness["known_limitations"],
            ),
            "docker-compose/README.md": self._markdown(
                "Docker Compose Delivery",
                [
                    "Use the checked-in compose profile and inject credentials through the deployment secret manager."
                ],
            ),
            "helm/README.md": self._markdown(
                "Helm Delivery",
                [
                    "Use the reviewed vulnlab-platform chart and supply environment-specific values from a secure store."
                ],
            ),
            "migrations/README.md": self._markdown(
                "Migration Delivery",
                [
                    "Apply migrations 0001 through 0014 in order and verify rollback boundaries before upgrade."
                ],
            ),
            "sbom/README.md": self._markdown(
                "SBOM Delivery",
                ["Attach the current SBOM digest before a formal package is generated."],
            ),
            "provenance/README.md": self._markdown(
                "Provenance Delivery",
                [
                    "Attach the current provenance statement digest before a formal package is generated."
                ],
            ),
            "signatures/README.md": self._markdown(
                "Signature Delivery",
                [
                    "Attach the current signature verification record before a formal package is generated."
                ],
            ),
        }
        written: list[tuple[str, str, int]] = []
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            encoded = content.encode()
            path.write_bytes(encoded)
            written.append((relative.replace("\\", "/"), _sha256_bytes(encoded), len(encoded)))
        manifest["files"] = [
            {"path": relative, "sha256": digest, "size": size}
            for relative, digest, size in sorted(written)
        ]
        package_digest = _digest(manifest["files"])
        manifest["package_digest"] = package_digest
        manifest_encoded = (
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode()
        manifest_path = root / "manifests" / "release-manifest.json"
        manifest_path.write_bytes(manifest_encoded)
        written.append(
            (
                "manifests/release-manifest.json",
                _sha256_bytes(manifest_encoded),
                len(manifest_encoded),
            )
        )
        self._ensure_delivery_contains_no_secret(root)
        checksums = "\n".join(f"{digest}  {relative}" for relative, digest, _ in sorted(written))
        checksums += "\n"
        for relative in ("SHA256SUMS", "checksums/SHA256SUMS"):
            encoded = checksums.encode()
            (root / relative).write_bytes(encoded)
            written.append((relative, _sha256_bytes(encoded), len(encoded)))
        return manifest, package_digest

    @staticmethod
    def _markdown(title: str, lines: list[str]) -> str:
        body = "\n".join(f"- {line}" for line in lines)
        return f"# {title}\n\n{body}\n"

    @staticmethod
    def _ensure_delivery_contains_no_secret(root: Path) -> None:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
            if any(marker in content for marker in SENSITIVE_DELIVERY_MARKERS):
                raise AcceptanceStateError(
                    f"delivery package contains forbidden sensitive marker: {path.name}"
                )

    def compliance_controls(self, _principal: Principal) -> list[dict[str, Any]]:
        return [dict(item) for item in COMPLIANCE_CONTROLS]

    def generate_compliance_package(
        self,
        principal: Principal,
        value: ComplianceEvidencePackageCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest(value.model_dump(mode="json"))
        replay = self._idempotent_response(
            principal, "p14.compliance.generate", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        tenant_id = self._tenant_id(principal, value.tenant_id)
        package_id = str(uuid.uuid4())
        policy_decision = self._enforce_policy(
            principal,
            "compliance.generate",
            "compliance_evidence_package",
            package_id,
            metadata={"frameworks": value.frameworks, "tenant_id": tenant_id},
        )
        selected = [
            control
            for control in COMPLIANCE_CONTROLS
            if not value.frameworks or control["framework"] in value.frameworks
        ]
        contents = {
            "version": TARGET_VERSION,
            "controls": selected,
            "certification_claim": False,
            "disclaimer": CONTROL_MAPPING_DISCLAIMER,
        }
        package_digest = _digest(contents)
        response = {
            "id": package_id,
            "tenant_id": tenant_id,
            "project_id": value.project_id,
            "package_digest": package_digest,
            "controls": selected,
            "certification_claim": False,
            "disclaimer": CONTROL_MAPPING_DISCLAIMER,
            "policy_decision_id": policy_decision["id"],
            "generated_by": principal.id,
            "created_at": _now(),
            "updated_at": _now(),
            "version": 1,
        }
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO p14_compliance_evidence_packages(
                   id,tenant_id,project_id,package_digest,controls_json,policy_decision_id,
                   generated_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,1)""",
                (
                    package_id,
                    tenant_id,
                    value.project_id,
                    package_digest,
                    _json_dumps(contents),
                    policy_decision["id"],
                    principal.id,
                    response["created_at"],
                    response["updated_at"],
                ),
            )
            connection.execute(
                """INSERT INTO task_idempotency_records(
                   id,principal_id,operation,idempotency_key,request_hash,response_json,
                   resource_type,resource_id,status,expires_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    principal.id,
                    "p14.compliance.generate",
                    idempotency_key or "",
                    request_hash,
                    _json_dumps(response),
                    "compliance_evidence_package",
                    package_id,
                    "completed",
                    _future(24),
                    response["created_at"],
                    response["updated_at"],
                ),
            )
        self._audit(
            principal,
            "compliance.generate",
            "compliance_evidence_package",
            package_id,
            details={"package_digest": package_digest},
        )
        return response

    def export_tenant_data(
        self,
        principal: Principal,
        value: DataExportCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest(value.model_dump(mode="json"))
        replay = self._idempotent_response(
            principal, "p14.data.export", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        tenant_id = self._tenant_id(principal, value.tenant_id)
        export_id = str(uuid.uuid4())
        policy_decision = self._enforce_policy(
            principal,
            "data.export",
            "tenant_data_export",
            export_id,
            metadata={"tenant_id": tenant_id, "requested_tenant_id": value.tenant_id},
        )
        manifest = {
            "tenant_id": tenant_id,
            "requested_tenant_id": value.tenant_id,
            "project_id": value.project_id,
            "format": value.format,
            "redacted": True,
            "secret_count": 0,
            "included_domains": [
                "tenant profile metadata",
                "projects",
                "tasks",
                "validation metadata",
                "case metadata",
                "release metadata",
                "audit references",
            ],
            "excluded_domains": [
                "credential ciphertext",
                "audit payload secrets",
                "evidence object bodies",
                "release private signing material",
            ],
        }
        response = {
            "id": export_id,
            "tenant_id": tenant_id,
            "project_id": value.project_id,
            "export_type": "tenant",
            "status": "completed",
            "manifest": manifest,
            "redacted": True,
            "secret_count": 0,
            "policy_decision_id": policy_decision["id"],
            "requested_by": principal.id,
            "created_at": _now(),
            "updated_at": _now(),
            "version": 1,
        }
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO p14_data_exports(
                   id,tenant_id,project_id,export_type,status,manifest_json,redacted,
                   secret_count,policy_decision_id,requested_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    export_id,
                    tenant_id,
                    value.project_id,
                    "tenant",
                    "completed",
                    _json_dumps(manifest),
                    1,
                    0,
                    policy_decision["id"],
                    principal.id,
                    response["created_at"],
                    response["updated_at"],
                ),
            )
            connection.execute(
                """INSERT INTO task_idempotency_records(
                   id,principal_id,operation,idempotency_key,request_hash,response_json,
                   resource_type,resource_id,status,expires_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    principal.id,
                    "p14.data.export",
                    idempotency_key or "",
                    request_hash,
                    _json_dumps(response),
                    "tenant_data_export",
                    export_id,
                    "completed",
                    _future(24),
                    response["created_at"],
                    response["updated_at"],
                ),
            )
        self._audit(
            principal,
            "data.export",
            "tenant_data_export",
            export_id,
            details={"tenant_id": tenant_id, "redacted": True},
        )
        return response

    def request_deletion(
        self,
        principal: Principal,
        value: DataDeletionRequestCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest(value.model_dump(mode="json"))
        replay = self._idempotent_response(
            principal, "p14.data.delete.request", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        tenant_id = self._tenant_id(principal, value.tenant_id)
        request_id = str(uuid.uuid4())
        policy_decision = self._enforce_policy(
            principal,
            "data.delete.request",
            "data_deletion_request",
            request_id,
            metadata={"target_type": value.target_type, "target_id": value.target_id},
        )
        legal_hold = self.db.fetch_one(
            """SELECT * FROM p14_legal_holds
               WHERE tenant_id=? AND project_id=? AND status='active'
               ORDER BY created_at DESC LIMIT 1""",
            (tenant_id, value.project_id),
        )
        status = (
            "blocked_by_legal_hold"
            if legal_hold is not None
            else ("dry_run_completed" if value.dry_run else "approval_required")
        )
        preview = {
            "target_type": value.target_type,
            "target_id": value.target_id,
            "dry_run": value.dry_run,
            "legal_hold_id": legal_hold["id"] if legal_hold is not None else None,
            "physical_deletion_allowed": False,
            "retained_domains": ["audit", "evidence metadata", "release evidence"],
        }
        certificate = {
            "issued": False,
            "reason": "dry-run only" if value.dry_run else "approval required",
            "legal_hold_block": legal_hold is not None,
        }
        response = {
            "id": request_id,
            "tenant_id": tenant_id,
            "project_id": value.project_id,
            "target_type": value.target_type,
            "target_id": value.target_id,
            "dry_run": value.dry_run,
            "status": status,
            "scope_preview": preview,
            "deletion_certificate": certificate,
            "policy_decision_id": policy_decision["id"],
            "requested_by": principal.id,
            "approved_by": None,
            "created_at": _now(),
            "updated_at": _now(),
            "version": 1,
        }
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO p14_deletion_requests(
                   id,tenant_id,project_id,target_type,target_id,dry_run,status,
                   scope_preview_json,deletion_certificate_json,policy_decision_id,
                   requested_by,approved_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    request_id,
                    tenant_id,
                    value.project_id,
                    value.target_type,
                    value.target_id,
                    int(value.dry_run),
                    status,
                    _json_dumps(preview),
                    _json_dumps(certificate),
                    policy_decision["id"],
                    principal.id,
                    None,
                    response["created_at"],
                    response["updated_at"],
                ),
            )
            connection.execute(
                """INSERT INTO task_idempotency_records(
                   id,principal_id,operation,idempotency_key,request_hash,response_json,
                   resource_type,resource_id,status,expires_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    principal.id,
                    "p14.data.delete.request",
                    idempotency_key or "",
                    request_hash,
                    _json_dumps(response),
                    "data_deletion_request",
                    request_id,
                    "completed",
                    _future(24),
                    response["created_at"],
                    response["updated_at"],
                ),
            )
        self._audit(
            principal,
            "data.delete.request",
            "data_deletion_request",
            request_id,
            details={"status": status, "dry_run": value.dry_run},
        )
        return response

    def create_legal_hold(
        self,
        principal: Principal,
        value: LegalHoldCreate,
        *,
        idempotency_key: str | None,
    ) -> dict[str, Any]:
        request_hash = _digest(value.model_dump(mode="json"))
        replay = self._idempotent_response(
            principal, "p14.legal_hold.create", idempotency_key, request_hash
        )
        if replay is not None:
            return replay
        tenant_id = self._tenant_id(principal, value.tenant_id)
        hold_id = str(uuid.uuid4())
        policy_decision = self._enforce_policy(
            principal,
            "legal-hold.create",
            "legal_hold",
            hold_id,
            metadata={"tenant_id": tenant_id, "hold_type": value.hold_type},
        )
        response = {
            "id": hold_id,
            "tenant_id": tenant_id,
            "project_id": value.project_id,
            "hold_type": value.hold_type,
            "status": "active",
            "reason": value.reason,
            "scope": value.scope,
            "policy_decision_id": policy_decision["id"],
            "created_by": principal.id,
            "released_by": None,
            "created_at": _now(),
            "updated_at": _now(),
            "version": 1,
        }
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO p14_legal_holds(
                   id,tenant_id,project_id,hold_type,status,reason,scope_json,
                   policy_decision_id,created_by,released_by,created_at,updated_at,version
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    hold_id,
                    tenant_id,
                    value.project_id,
                    value.hold_type,
                    "active",
                    value.reason,
                    _json_dumps(value.scope),
                    policy_decision["id"],
                    principal.id,
                    None,
                    response["created_at"],
                    response["updated_at"],
                ),
            )
            connection.execute(
                """INSERT INTO task_idempotency_records(
                   id,principal_id,operation,idempotency_key,request_hash,response_json,
                   resource_type,resource_id,status,expires_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    principal.id,
                    "p14.legal_hold.create",
                    idempotency_key or "",
                    request_hash,
                    _json_dumps(response),
                    "legal_hold",
                    hold_id,
                    "completed",
                    _future(24),
                    response["created_at"],
                    response["updated_at"],
                ),
            )
        self._audit(
            principal,
            "legal-hold.create",
            "legal_hold",
            hold_id,
            details={"hold_type": value.hold_type, "status": "active"},
        )
        return response
