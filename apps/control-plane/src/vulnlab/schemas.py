from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


class UserCreate(APIModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    role: Role


class UserUpdate(APIModel):
    role: Role | None = None
    active: bool | None = None

    @model_validator(mode="after")
    def at_least_one_change(self) -> UserUpdate:
        if self.role is None and self.active is None:
            raise ValueError("role or active must be provided")
        return self


class UserResponse(APIModel):
    id: str
    username: str
    role: Role
    active: bool
    created_at: datetime


class UserCreated(UserResponse):
    api_key: str = Field(description="Returned once; store it securely")


class ProviderCreate(APIModel):
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["mock", "openai_compatible", "ollama"]
    base_url: HttpUrl | None = None
    model: str = Field(min_length=1, max_length=128)
    api_key: str | None = Field(default=None, max_length=4096)
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=10_000)
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10_000)
    token_quota_per_minute: int = Field(default=100_000, ge=128, le=10_000_000)
    timeout_seconds: float = Field(default=30, ge=1, le=300)
    input_cost_per_1k: float = Field(default=0.0, ge=0, le=10_000)
    output_cost_per_1k: float = Field(default=0.0, ge=0, le=10_000)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def validate_url(cls, value: HttpUrl | None, info: Any) -> HttpUrl | None:
        kind = info.data.get("kind")
        if kind != "mock" and value is None:
            raise ValueError("base_url is required for non-mock providers")
        return value

    @model_validator(mode="after")
    def required_endpoint(self) -> ProviderCreate:
        if self.kind != "mock" and self.base_url is None:
            raise ValueError("base_url is required for non-mock providers")
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("capabilities must be unique")
        return self


class ProviderResponse(APIModel):
    id: str
    name: str
    kind: str
    base_url: str | None
    model: str
    has_api_key: bool
    credential_ref: str | None
    enabled: bool
    priority: int
    rate_limit_per_minute: int
    token_quota_per_minute: int
    timeout_seconds: float
    input_cost_per_1k: float
    output_cost_per_1k: float
    capabilities: list[str]
    config: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ChatMessage(APIModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=50_000)


class ModelToolDefinition(APIModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    description: str = Field(min_length=1, max_length=500)
    input_schema: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def valid_schema_shape(self) -> ModelToolDefinition:
        schema_type = self.input_schema.get("type", "object")
        if schema_type != "object":
            raise ValueError("tool input_schema must be a JSON object schema")
        return self


class ModelResponseFormat(APIModel):
    type: Literal["text", "json_object"] = "text"


class ModelRequest(APIModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=64)
    purpose: Literal["planning", "summarization", "reporting", "tool_selection"] = "planning"
    max_tokens: int = Field(default=512, ge=16, le=4096)
    response_format: ModelResponseFormat = Field(default_factory=ModelResponseFormat)
    tools: list[ModelToolDefinition] = Field(default_factory=list, max_length=16)
    stream: bool = False

    @model_validator(mode="after")
    def unique_tools(self) -> ModelRequest:
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool names must be unique")
        return self


class ScopeCreate(APIModel):
    name: str = Field(min_length=3, max_length=100)
    target_pattern: str = Field(min_length=1, max_length=255)
    protocols: list[Literal["http", "https", "tcp"]] = Field(min_length=1, max_length=3)
    ports: list[int] = Field(min_length=1, max_length=32)
    expires_at: datetime | None = None
    approved: bool = False

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, value: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in value):
            raise ValueError("ports must be between 1 and 65535")
        return sorted(set(value))


class ScopeResponse(APIModel):
    id: str
    name: str
    target_pattern: str
    protocols: list[str]
    ports: list[int]
    expires_at: datetime | None
    approved: bool
    approved_by: str | None = None
    approved_at: datetime | None = None
    approval_reason: str | None = None
    scope_hash: str
    created_by: str
    created_at: datetime


class TargetProfileCreate(APIModel):
    name: str = Field(min_length=3, max_length=100)
    target: str = Field(min_length=1, max_length=2048)
    proxy_url: HttpUrl | None = None
    proxy_scope_id: str | None = None
    intent: Literal["asset_inventory", "vulnerability_validation", "defensive_regression"]
    indicators: list[str] = Field(default_factory=list, max_length=64)
    scope_id: str

    @field_validator("proxy_scope_id")
    @classmethod
    def proxy_scope_required(cls, value: str | None, info: Any) -> str | None:
        if info.data.get("proxy_url") is not None and value is None:
            raise ValueError("proxy_scope_id is required when proxy_url is configured")
        return value

    @model_validator(mode="after")
    def required_proxy_scope(self) -> TargetProfileCreate:
        if self.proxy_url is not None and self.proxy_scope_id is None:
            raise ValueError("proxy_scope_id is required when proxy_url is configured")
        if self.proxy_url is None and self.proxy_scope_id is not None:
            raise ValueError("proxy_scope_id cannot be set without proxy_url")
        return self


class TargetProfileResponse(APIModel):
    id: str
    name: str
    target: str
    proxy_url: str | None
    proxy_scope_id: str | None
    intent: str
    indicators: list[str]
    scope_id: str
    created_by: str
    created_at: datetime


class TaskCreate(APIModel):
    title: str = Field(min_length=3, max_length=200)
    target: str = Field(min_length=1, max_length=2048)
    intent: Literal["asset_inventory", "vulnerability_validation", "defensive_regression"]
    indicators: list[str] = Field(default_factory=list, max_length=64)
    scope_id: str


class TaskActionRequest(APIModel):
    reason: str | None = Field(default=None, max_length=500)


class TaskResponse(APIModel):
    id: str
    title: str
    target: str
    intent: str
    indicators: list[str]
    scope_id: str
    status: str
    approval_status: str
    created_by: str
    assigned_skills: list[str]
    workflow_name: str = "p3.synthetic.defensive"
    workflow_version: str = "1.0"
    plan: dict[str, Any] | None
    result: dict[str, Any] | None
    error: str | None
    current_stage: str | None = None
    pause_requested: bool = False
    cancel_requested: bool = False
    retry_count: int = 0
    max_retries: int = 2
    fencing_token: int = 0
    created_at: datetime
    updated_at: datetime


class ApprovalRequest(APIModel):
    approved: bool
    reason: str = Field(min_length=3, max_length=500)


class SkillCreate(APIModel):
    name: str = Field(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9_.-]+$")
    version: str = Field(default="1.0", min_length=1, max_length=40)
    description: str = Field(min_length=3, max_length=500)
    risk_level: Literal["low", "medium", "high"]
    required_role: Role
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    permissions: list[str] = Field(default_factory=list, max_length=32)
    resource_limits: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=30, ge=1, le=600)
    execution_type: Literal["internal", "webhook", "sandbox_deferred"] = "internal"
    tool_dependencies: list[str] = Field(default_factory=list, max_length=32)
    approval_required: bool = False


class SkillResponse(APIModel):
    id: str
    name: str
    version: str
    description: str
    risk_level: str
    required_role: Role
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    permissions: list[str]
    resource_limits: dict[str, Any]
    timeout_seconds: float
    execution_type: str
    tool_dependencies: list[str]
    approval_required: bool
    enabled: bool
    builtin: bool
    invocation_count: int = 0
    success_count: int = 0
    failure_count: int = 0


class AgentCreate(APIModel):
    name: str = Field(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9_.-]+$")
    version: str = Field(default="1.0", min_length=1, max_length=40)
    description: str = Field(min_length=3, max_length=500)
    responsibilities: list[str] = Field(min_length=1, max_length=16)
    input_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    output_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    allowed_tools: list[str] = Field(default_factory=list, max_length=32)
    data_scope: Literal["task", "project", "tenant"] = "task"
    token_budget: int = Field(default=2048, ge=0, le=1_000_000)
    timeout_seconds: float = Field(default=60, ge=1, le=3600)
    risk_level: Literal["low", "medium", "high"] = "low"
    retry_policy: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def no_duplicate_tools(self) -> AgentCreate:
        if len(self.allowed_tools) != len(set(self.allowed_tools)):
            raise ValueError("allowed_tools must be unique")
        return self


class AgentResponse(AgentCreate):
    id: str
    enabled: bool
    builtin: bool
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime


class WorkflowStageDefinition(APIModel):
    code: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_.-]+$")
    display_name: str = Field(min_length=1, max_length=120)
    agent_name: str = Field(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9_.-]+$")
    agent_version: str = Field(default="1.0", min_length=1, max_length=40)
    skill_name: str = Field(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9_.-]+$")
    skill_version: str = Field(default="1.0", min_length=1, max_length=40)
    depends_on: list[str] = Field(default_factory=list, max_length=16)
    max_attempts: int = Field(default=1, ge=1, le=10)


class WorkflowCreate(APIModel):
    name: str = Field(min_length=3, max_length=120, pattern=r"^[a-z][a-z0-9_.-]+$")
    version: str = Field(default="1.0", min_length=1, max_length=40)
    description: str = Field(min_length=3, max_length=800)
    stages: list[WorkflowStageDefinition] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def valid_dag(self) -> WorkflowCreate:
        codes = [stage.code for stage in self.stages]
        if len(codes) != len(set(codes)):
            raise ValueError("workflow stage codes must be unique")
        seen: set[str] = set()
        for stage in self.stages:
            missing = sorted(set(stage.depends_on) - seen)
            if missing:
                raise ValueError(
                    f"stage {stage.code} depends on unknown or later stages: {', '.join(missing)}"
                )
            seen.add(stage.code)
        return self


class WorkflowResponse(WorkflowCreate):
    id: str
    enabled: bool
    builtin: bool
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime


class TaskStageResponse(APIModel):
    id: str
    task_id: str
    stage_code: str
    display_name: str
    sequence_no: int
    agent_name: str
    agent_version: str
    skill_name: str
    skill_version: str
    depends_on: list[str]
    status: str
    attempt: int
    max_attempts: int
    checkpoint: dict[str, Any] | None = None
    output: dict[str, Any] | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class TaskExecutionResponse(APIModel):
    id: str
    task_id: str
    worker_id: str
    fencing_token: int
    status: str
    started_at: datetime
    heartbeat_at: datetime
    finished_at: datetime | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime


class TaskDeadLetterResponse(APIModel):
    id: str
    task_id: str | None
    queue_message_id: str | None
    reason: str
    payload: dict[str, Any]
    created_at: datetime


class ProbeStep(APIModel):
    kind: Literal["tcp_connect", "http_request", "assertion"]
    host: str
    port: int = Field(ge=1, le=65535)
    method: Literal["HEAD", "GET"] | None = None
    path: str | None = Field(default=None, max_length=1024)
    expected_status: list[int] = Field(default_factory=list, max_length=16)
    body_pattern: str | None = Field(default=None, max_length=256)

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str | None) -> str | None:
        if value is not None and (not value.startswith("/") or "\r" in value or "\n" in value):
            raise ValueError("HTTP path must be an absolute path without control characters")
        return value


class ValidationPlan(APIModel):
    version: str = "1.0"
    task_id: str
    destructive: Literal[False] = False
    objectives: list[str]
    steps: list[ProbeStep] = Field(max_length=32)
    rollback: list[str]


class ValidationPlanCreate(APIModel):
    objectives: list[str] = Field(min_length=1, max_length=32)
    steps: list[ProbeStep] = Field(min_length=1, max_length=32)
    rollback: list[str] = Field(min_length=1, max_length=32)


class ValidationPlanReview(APIModel):
    approved: bool
    reason: str = Field(min_length=3, max_length=500)


class ValidationPlanResponse(APIModel):
    id: str
    task_id: str
    status: Literal["draft", "submitted", "approved", "rejected", "revoked"]
    plan: dict[str, Any]
    plan_hash: str
    policy_decision_ids: list[str]
    created_by: str
    submitted_at: datetime | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    review_reason: str | None
    created_at: datetime
    updated_at: datetime


class ValidationExecutionCreate(APIModel):
    template_id: str | None = Field(default=None, max_length=120)


class ValidationExecutionReview(APIModel):
    accepted: bool
    reason: str = Field(min_length=3, max_length=500)


class ValidationTemplateResponse(APIModel):
    id: str
    version: str
    name: str
    description: str
    risk_level: Literal["low", "medium", "high"]
    enabled: bool
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    timeout_seconds: float
    sandbox: dict[str, Any]


class ValidationExecutionResponse(APIModel):
    id: str
    plan_id: str
    task_id: str
    tenant_id: str
    template_id: str
    template_version: str
    status: Literal[
        "QUEUED",
        "PROVISIONING",
        "RUNNING",
        "COLLECTING_EVIDENCE",
        "VERIFYING",
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
        "EXPIRED",
        "POLICY_REJECTED",
        "APPROVAL_REVOKED",
        "SCOPE_INVALID",
        "SANDBOX_FAILED",
        "RESOURCE_EXCEEDED",
        "EXECUTION_TIMEOUT",
        "EVIDENCE_INCOMPLETE",
    ]
    trace_id: str
    sandbox_id: str
    approval_id: str
    policy_decision_id: str
    idempotency_key: str | None
    queue_message_id: str | None
    result: dict[str, Any]
    error: str | None
    review_decision: Literal["accepted", "rejected"] | None
    review_reason: str | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    retry_of: str | None
    created_by: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ValidationExecutionEventResponse(APIModel):
    id: int
    execution_id: str
    event_type: str
    status: str
    payload: dict[str, Any]
    created_at: datetime


class ValidationExecutionEvidenceResponse(APIModel):
    id: str
    execution_id: str
    task_id: str
    evidence_item_id: str | None
    title: str
    artifact_ref: str
    content_sha256: str
    metadata: dict[str, Any]
    created_at: datetime


Severity = Literal["informational", "low", "medium", "high", "critical"]
CaseStatus = Literal[
    "DRAFT",
    "TRIAGE",
    "VALIDATION_PENDING",
    "VALIDATED",
    "REMEDIATION_PLANNED",
    "REMEDIATION_IN_PROGRESS",
    "RETEST_PENDING",
    "REMEDIATED",
    "ACCEPTED_RISK",
    "FALSE_POSITIVE",
    "INCONCLUSIVE",
    "CLOSED",
]


class VulnerabilityCaseCreate(APIModel):
    title: str = Field(min_length=3, max_length=240)
    summary: str = Field(min_length=3, max_length=5000)
    severity: Severity = "medium"
    project_id: str = Field(default="default", min_length=1, max_length=120)
    source: Literal["VALIDATION", "MANUAL", "IMPORT"] = "MANUAL"
    external_ref: str | None = Field(default=None, max_length=240)
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityCasePatch(APIModel):
    expected_version: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=3, max_length=240)
    summary: str | None = Field(default=None, min_length=3, max_length=5000)
    severity: Severity | None = None
    status: CaseStatus | None = None
    metadata: dict[str, Any] | None = None

    @model_validator(mode="after")
    def at_least_one_case_change(self) -> VulnerabilityCasePatch:
        if (
            self.title is None
            and self.summary is None
            and self.severity is None
            and self.status is None
            and self.metadata is None
        ):
            raise ValueError("at least one case field must be changed")
        return self


class VulnerabilityCaseResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    title: str
    summary: str
    severity: Severity
    status: CaseStatus
    source: str
    external_ref: str | None
    metadata: dict[str, Any]
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime
    version: int


class CaseFindingCreate(APIModel):
    title: str = Field(min_length=3, max_length=240)
    description: str = Field(min_length=3, max_length=5000)
    affected_component: str | None = Field(default=None, max_length=240)
    risk_level: Severity = "medium"
    status: Literal["CANDIDATE", "VALIDATED", "FALSE_POSITIVE", "INCONCLUSIVE"] = "CANDIDATE"
    validation_execution_id: str | None = None
    evidence_id: str | None = None
    project_id: str | None = Field(default=None, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CaseFindingResponse(APIModel):
    id: str
    case_id: str
    tenant_id: str
    project_id: str
    validation_execution_id: str | None
    evidence_id: str | None
    title: str
    description: str
    affected_component: str | None
    risk_level: Severity
    status: Literal["CANDIDATE", "VALIDATED", "FALSE_POSITIVE", "REMEDIATED", "INCONCLUSIVE"]
    metadata: dict[str, Any]
    created_by: str
    created_at: datetime
    updated_at: datetime
    version: int


class RemediationProposalCreate(APIModel):
    source: Literal["AI_GENERATED", "KNOWLEDGE_BASE", "VENDOR_ADVISORY", "MANUAL"]
    title: str = Field(min_length=3, max_length=240)
    description: str = Field(min_length=3, max_length=10000)
    risk_level: Literal["low", "medium", "high"] = "medium"
    knowledge_refs: list[str] = Field(default_factory=list, max_length=64)
    model_invocation_id: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)


class RemediationProposalResponse(APIModel):
    id: str
    case_id: str
    tenant_id: str
    project_id: str
    source: Literal["AI_GENERATED", "KNOWLEDGE_BASE", "VENDOR_ADVISORY", "MANUAL"]
    title: str
    description: str
    risk_level: Literal["low", "medium", "high"]
    knowledge_refs: list[str]
    model_invocation_id: str | None
    provenance: dict[str, Any]
    status: Literal["PROPOSED", "APPROVED", "REJECTED", "CHANGES_REQUESTED"]
    proposed_by: str
    created_at: datetime
    updated_at: datetime
    version: int


class RemediationDecisionCreate(APIModel):
    decision: Literal["APPROVED", "REJECTED", "CHANGES_REQUESTED"]
    reason: str = Field(min_length=3, max_length=2000)
    automated: bool = False


class RemediationDecisionResponse(APIModel):
    id: str
    proposal_id: str
    case_id: str
    tenant_id: str
    project_id: str
    decision: Literal["APPROVED", "REJECTED", "CHANGES_REQUESTED"]
    reason: str
    automated: bool
    decided_by: str
    decided_at: datetime
    created_at: datetime
    updated_at: datetime
    version: int


class RemediationImplementationCreate(APIModel):
    implementation_ref: str = Field(min_length=3, max_length=500)
    description: str = Field(min_length=3, max_length=5000)
    implemented_at: datetime | None = None
    verification_notes: str | None = Field(default=None, max_length=5000)


class RemediationImplementationResponse(APIModel):
    id: str
    decision_id: str
    proposal_id: str
    case_id: str
    tenant_id: str
    project_id: str
    implementation_ref: str
    description: str
    implemented_by: str
    implemented_at: datetime
    verification_notes: str | None
    created_at: datetime
    updated_at: datetime
    version: int


class RetestRequestCreate(APIModel):
    finding_id: str
    original_execution_id: str
    remediation_implementation_id: str


class RetestRequestResponse(APIModel):
    id: str
    case_id: str
    finding_id: str
    tenant_id: str
    project_id: str
    original_execution_id: str
    remediation_implementation_id: str
    retest_execution_id: str
    status: Literal["REQUESTED", "QUEUED", "RUNNING", "COMPLETED", "CANCELLED", "INCONCLUSIVE"]
    template_id: str
    template_version: str
    template_version_changed: bool
    requested_by: str
    requested_at: datetime
    created_at: datetime
    updated_at: datetime
    version: int


class ValidationComparisonResponse(APIModel):
    id: str
    retest_id: str
    case_id: str
    finding_id: str
    tenant_id: str
    project_id: str
    original_execution_id: str
    retest_execution_id: str
    result: Literal[
        "REMEDIATED",
        "PARTIALLY_REMEDIATED",
        "NOT_REMEDIATED",
        "REGRESSION",
        "INCONCLUSIVE",
    ]
    initial_status: str
    retest_status: str
    success_condition_diff: dict[str, Any]
    key_response_diff: dict[str, Any]
    component_version_diff: dict[str, Any]
    evidence_sha256: dict[str, Any]
    risk_level_change: str | None
    residual_risk: str | None
    recommendation: str | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    version: int


class CaseDispositionCreate(APIModel):
    disposition: Literal["REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE", "INCONCLUSIVE"]
    reason: str = Field(min_length=3, max_length=3000)
    residual_risk: str | None = Field(default=None, max_length=3000)
    expected_version: int = Field(ge=1)
    human_confirmed: Literal[True] = True


class CaseDispositionResponse(APIModel):
    id: str
    case_id: str
    tenant_id: str
    project_id: str
    disposition: Literal["REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE", "INCONCLUSIVE"]
    reason: str
    residual_risk: str | None
    human_confirmed: bool
    decided_by: str
    decided_at: datetime
    created_at: datetime
    updated_at: datetime
    version: int


class CaseReportCreate(APIModel):
    title: str | None = Field(default=None, max_length=240)


class CaseCloseRequest(APIModel):
    expected_version: int = Field(ge=1)
    reason: str | None = Field(default=None, max_length=1000)


class CaseReportResponse(APIModel):
    id: str
    case_id: str
    tenant_id: str
    project_id: str
    title: str
    report: dict[str, Any]
    generated_by: str
    generated_at: datetime
    created_at: datetime
    updated_at: datetime
    version: int


class VulnerabilityCaseDetailResponse(APIModel):
    case: VulnerabilityCaseResponse
    findings: list[CaseFindingResponse]
    remediation_proposals: list[RemediationProposalResponse]
    remediation_decisions: list[RemediationDecisionResponse]
    remediation_implementations: list[RemediationImplementationResponse]
    retests: list[RetestRequestResponse]
    comparisons: list[ValidationComparisonResponse]
    dispositions: list[CaseDispositionResponse]
    reports: list[CaseReportResponse]
    audit_events: list[dict[str, Any]]


class SandboxRequest(APIModel):
    task_id: str | None = None
    argv: list[str] = Field(min_length=1, max_length=32)
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    image: str | None = Field(default=None, max_length=200)

    @field_validator("argv")
    @classmethod
    def no_control_chars(cls, value: list[str]) -> list[str]:
        if any(any(char in arg for char in ("\x00", "\r", "\n")) for arg in value):
            raise ValueError("arguments cannot contain control characters")
        return value


class SandboxResponse(APIModel):
    id: str
    mode: str
    status: str
    exit_code: int | None
    stdout: str
    stderr: str


class ContextMessageCreate(APIModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(min_length=1, max_length=20_000)
    visibility: Literal["private", "task"] = "task"


class CheckpointResponse(APIModel):
    id: str
    task_id: str
    summary: str
    state: dict[str, Any]
    summary_hash: str
    state_hash: str
    message_count: int
    evidence_count: int = 0
    restore_policy_hash: str
    created_at: datetime


class RAGDocumentCreate(APIModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=500_000)
    source: str = Field(min_length=1, max_length=500)
    classification: Literal["public", "internal", "restricted"] = "internal"
    version: str = Field(default="1", min_length=1, max_length=50)
    tags: list[str] = Field(default_factory=list, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RAGSearchRequest(APIModel):
    query: str = Field(min_length=2, max_length=1000)
    top_k: int = Field(default=5, ge=1, le=20)
    classifications: list[Literal["public", "internal", "restricted"]] | None = None


class EvidenceCreate(APIModel):
    title: str = Field(min_length=1, max_length=200)
    source_type: Literal["manual", "rag_chunk", "checkpoint", "task_output"] = "manual"
    source_ref: str = Field(default="manual://operator-note", min_length=1, max_length=500)
    content: str = Field(min_length=1, max_length=100_000)
    classification: Literal["public", "internal", "restricted"] = "internal"
    trust: Literal["untrusted_evidence_only", "operator_attested", "system_observed"] = (
        "untrusted_evidence_only"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgePackRequest(APIModel):
    query: str = Field(min_length=2, max_length=1000)
    top_k: int = Field(default=5, ge=1, le=20)
    include_private_context: bool = False
    classifications: list[Literal["public", "internal", "restricted"]] | None = None


class PolicyEvaluationRequest(APIModel):
    action: Literal[
        "asset.probe",
        "sandbox.run",
        "validation.execute",
        "case.create",
        "case.update",
        "case.confirm",
        "case.disposition",
        "remediation.propose",
        "remediation.approve",
        "remediation.implement",
        "validation.retest",
        "comparison.review",
        "case.close",
        "report.generate",
        "task.execute",
        "context.restore",
        "rag.search",
    ]
    resource_type: str = Field(default="task", min_length=1, max_length=80)
    resource_id: str = Field(default="ad-hoc", min_length=1, max_length=200)
    task_id: str | None = None
    scope_id: str | None = None
    target: str | None = Field(default=None, max_length=2048)
    ports: list[int] = Field(default_factory=list, max_length=32)
    argv: list[str] = Field(default_factory=list, max_length=32)
    destructive: bool = False
    reason: str | None = Field(default=None, max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyDecisionResponse(APIModel):
    id: str
    action: str
    resource_type: str
    resource_id: str
    decision: Literal["allow", "deny", "requires_approval"]
    reason: str
    details: dict[str, Any]
    policy_hash: str
    created_at: datetime


class AssetProbeRequest(APIModel):
    target: str = Field(min_length=1, max_length=2048)
    scope_id: str
    ports: list[int] = Field(min_length=1, max_length=16)
    timeout_seconds: float = Field(default=1.0, ge=0.1, le=5.0)

    @field_validator("ports")
    @classmethod
    def unique_ports(cls, value: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in value):
            raise ValueError("invalid port")
        return sorted(set(value))


class AuditVerifyResponse(APIModel):
    valid: bool
    entries: int
    first_invalid_id: int | None = None


class ErrorResponse(APIModel):
    detail: str
    request_id: str | None = None
