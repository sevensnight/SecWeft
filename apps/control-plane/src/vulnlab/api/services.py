from __future__ import annotations

from dataclasses import dataclass

from .. import __version__
from ..agent_registry import AgentRegistry
from ..audit import AuditService
from ..case_management import CaseManagementService
from ..config import Settings
from ..context import ContextService
from ..enterprise import EnterpriseServices, build_enterprise_services
from ..evaluation_governance import EvaluationGovernanceService
from ..evidence import EvidenceService
from ..model_gateway import ModelGateway, ProviderStore
from ..operational_resilience import OperationalResilienceService
from ..orchestrator import Orchestrator
from ..policy import PolicyService
from ..rag import RAGService
from ..repository import ControlPlaneRepository, build_control_plane_repository
from ..sandbox import SandboxService
from ..scope import ScopeService
from ..security import SecurityService
from ..skills import SkillRegistry
from ..validation import ValidationPlanService
from ..validation_evidence_store import EvidenceStore, build_evidence_store
from ..validation_execution import ValidationExecutionService
from ..validation_queue import ValidationQueue, build_validation_queue
from ..validation_sandbox import SandboxBackend, build_sandbox_backend


@dataclass(slots=True)
class Services:
    settings: Settings
    db: ControlPlaneRepository
    security: SecurityService
    audit: AuditService
    providers: ProviderStore
    gateway: ModelGateway
    scope: ScopeService
    skills: SkillRegistry
    agents: AgentRegistry
    context: ContextService
    rag: RAGService
    evidence: EvidenceService
    policy: PolicyService
    validation: ValidationPlanService
    validation_queue: ValidationQueue
    validation_sandbox: SandboxBackend
    validation_evidence_store: EvidenceStore
    validation_execution: ValidationExecutionService
    cases: CaseManagementService
    evaluations: EvaluationGovernanceService
    operations: OperationalResilienceService
    sandbox: SandboxService
    orchestrator: Orchestrator
    enterprise: EnterpriseServices | None = None

    def close(self) -> None:
        close_queue = getattr(self.validation_queue, "close", None)
        if close_queue is not None:
            close_queue()
        if self.enterprise is not None:
            self.enterprise.close()


def build_services(settings: Settings) -> Services:
    """Compose the current modular-monolith adapters behind explicit service interfaces."""
    settings.prepare()
    db = build_control_plane_repository(settings)
    db.initialize()
    security = SecurityService(db, settings.audit_key)
    if settings.auth_mode == "compatibility":
        security.bootstrap_admin(settings.admin_key)
    audit = AuditService(db, settings.audit_key)
    if db.fetch_one("SELECT id FROM audit_logs LIMIT 1") is None:
        audit.record(
            "system", "system.initialize", "system", "vulnlab", details={"version": __version__}
        )
    providers = ProviderStore(db, settings.fernet, audit)
    providers.ensure_mock()
    scope_service = ScopeService(db, settings)
    skills = SkillRegistry(db, audit)
    skills.ensure_builtins()
    agents = AgentRegistry(db, audit)
    agents.ensure_builtins()
    context = ContextService(db, audit)
    rag = RAGService(db, audit)
    evidence = EvidenceService(db, audit)
    policy = PolicyService(db, scope_service, settings, audit)
    validation = ValidationPlanService(db, policy, audit)
    validation_queue = build_validation_queue(db, settings)
    validation_sandbox = build_sandbox_backend(settings, scope_service)
    validation_evidence_store = build_evidence_store(settings)
    validation_execution = ValidationExecutionService(
        db,
        settings,
        scope_service,
        evidence,
        policy,
        audit,
        validation_queue,
        validation_sandbox,
        validation_evidence_store,
    )
    gateway = ModelGateway(providers, audit)
    cases = CaseManagementService(db, policy, audit, validation_execution)
    evaluations = EvaluationGovernanceService(db, policy, audit, gateway)
    operations = OperationalResilienceService(db, settings, validation_evidence_store)
    sandbox = SandboxService(db, settings, audit)
    orchestrator = Orchestrator(db, scope_service, skills, agents, audit, settings.max_concurrency)
    enterprise = build_enterprise_services(settings) if settings.auth_mode == "oidc" else None
    return Services(
        settings=settings,
        db=db,
        security=security,
        audit=audit,
        providers=providers,
        gateway=gateway,
        scope=scope_service,
        skills=skills,
        agents=agents,
        context=context,
        rag=rag,
        evidence=evidence,
        policy=policy,
        validation=validation,
        validation_queue=validation_queue,
        validation_sandbox=validation_sandbox,
        validation_evidence_store=validation_evidence_store,
        validation_execution=validation_execution,
        cases=cases,
        evaluations=evaluations,
        operations=operations,
        sandbox=sandbox,
        orchestrator=orchestrator,
        enterprise=enterprise,
    )
