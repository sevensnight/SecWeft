from __future__ import annotations

from dataclasses import dataclass

from .. import __version__
from ..agent_registry import AgentRegistry
from ..audit import AuditService
from ..config import Settings
from ..context import ContextService
from ..db import Database
from ..enterprise import EnterpriseServices, build_enterprise_services
from ..evidence import EvidenceService
from ..model_gateway import ModelGateway, ProviderStore
from ..orchestrator import Orchestrator
from ..rag import RAGService
from ..sandbox import SandboxService
from ..scope import ScopeService
from ..security import SecurityService
from ..skills import SkillRegistry


@dataclass(slots=True)
class Services:
    settings: Settings
    db: Database
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
    sandbox: SandboxService
    orchestrator: Orchestrator
    enterprise: EnterpriseServices | None = None

    def close(self) -> None:
        if self.enterprise is not None:
            self.enterprise.close()


def build_services(settings: Settings) -> Services:
    """Compose the current modular-monolith adapters behind explicit service interfaces."""
    settings.prepare()
    db = Database(settings.db_path)
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
    sandbox = SandboxService(db, settings, audit)
    orchestrator = Orchestrator(db, scope_service, skills, agents, audit, settings.max_concurrency)
    enterprise = build_enterprise_services(settings) if settings.auth_mode == "oidc" else None
    return Services(
        settings=settings,
        db=db,
        security=security,
        audit=audit,
        providers=providers,
        gateway=ModelGateway(providers, audit),
        scope=scope_service,
        skills=skills,
        agents=agents,
        context=context,
        rag=rag,
        evidence=evidence,
        sandbox=sandbox,
        orchestrator=orchestrator,
        enterprise=enterprise,
    )
