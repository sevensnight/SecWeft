from __future__ import annotations

import uuid
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


EvaluationStatus = Literal[
    "DRAFT",
    "EVALUATING",
    "PASSED",
    "FAILED",
    "REVIEW_PENDING",
    "APPROVED",
    "REJECTED",
    "PROMOTED",
    "ROLLED_BACK",
    "CANCELLED",
]
EvaluationType = Literal[
    "deterministic_offline",
    "real_model",
    "controlled_e2e",
    "human_blind_review",
]
ScoringMethod = Literal[
    "deterministic_rule",
    "schema_validation",
    "exact_match",
    "set_comparison",
    "human_annotation",
    "restricted_llm_judge",
]


def default_scoring_methods() -> list[ScoringMethod]:
    return ["deterministic_rule", "set_comparison"]


class EvaluationSuiteCreate(APIModel):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=3, max_length=2000)
    project_id: str = Field(default="default", min_length=1, max_length=120)
    version: str = Field(default="1.0", min_length=1, max_length=80)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluationSuiteResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    name: str
    description: str
    version: str
    status: Literal["DRAFT", "ACTIVE", "ARCHIVED"]
    metadata: dict[str, Any]
    created_by: str
    created_at: datetime
    updated_at: datetime
    version_no: int


class EvaluationDatasetCreate(APIModel):
    suite_id: str
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=3000)
    version: str = Field(default="1.0", min_length=1, max_length=80)
    project_id: str = Field(default="default", min_length=1, max_length=120)
    ground_truth_version: str = Field(min_length=1, max_length=120)
    published: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluationDatasetResponse(APIModel):
    id: str
    suite_id: str
    tenant_id: str
    project_id: str
    name: str
    description: str
    version: str
    ground_truth_version: str
    published: bool
    immutable: bool
    dataset_hash: str
    metadata: dict[str, Any]
    created_by: str
    created_at: datetime
    updated_at: datetime
    version_no: int


class EvaluationCaseCreate(APIModel):
    external_id: str = Field(min_length=1, max_length=160)
    input: dict[str, Any] = Field(default_factory=dict)
    expected_output: str | None = Field(default=None, max_length=20_000)
    accepted_conclusions: list[str] = Field(default_factory=list, max_length=64)
    forbidden_conclusions: list[str] = Field(default_factory=list, max_length=64)
    expected_citations: list[str] = Field(default_factory=list, max_length=64)
    expected_template: str | None = Field(default=None, max_length=120)
    expected_policy_result: Literal["allow", "deny", "requires_approval"] | None = None
    required_evidence_fields: list[str] = Field(default_factory=list, max_length=64)
    allowed_tools: list[str] = Field(default_factory=list, max_length=64)
    forbidden_tools: list[str] = Field(default_factory=list, max_length=64)
    maximum_token_budget: int = Field(default=4096, ge=1, le=1_000_000)
    maximum_cost: float = Field(default=1.0, ge=0, le=10_000)
    maximum_latency_ms: int = Field(default=30_000, ge=1, le=3_600_000)
    scoring_method: list[ScoringMethod] = Field(
        default_factory=default_scoring_methods,
        min_length=1,
        max_length=6,
    )
    ground_truth_version: str = Field(min_length=1, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def explicit_ground_truth(self) -> EvaluationCaseCreate:
        has_truth = bool(
            self.expected_output
            or self.accepted_conclusions
            or self.expected_citations
            or self.expected_template
            or self.expected_policy_result
            or self.required_evidence_fields
        )
        if not has_truth:
            raise ValueError("evaluation case must define explicit ground truth")
        if self.scoring_method == ["restricted_llm_judge"]:
            raise ValueError("restricted LLM judge cannot be the only scoring method")
        if self.metadata.get("ground_truth_source") == "model_only":
            raise ValueError("ground truth cannot be only another model's score")
        return self


class EvaluationCaseResponse(APIModel):
    id: str
    dataset_id: str
    tenant_id: str
    project_id: str
    external_id: str
    input: dict[str, Any]
    expected_output: str | None
    accepted_conclusions: list[str]
    forbidden_conclusions: list[str]
    expected_citations: list[str]
    expected_template: str | None
    expected_policy_result: Literal["allow", "deny", "requires_approval"] | None
    required_evidence_fields: list[str]
    allowed_tools: list[str]
    forbidden_tools: list[str]
    maximum_token_budget: int
    maximum_cost: float
    maximum_latency_ms: int
    scoring_method: list[ScoringMethod]
    ground_truth_version: str
    ground_truth_hash: str
    metadata: dict[str, Any]
    created_by: str
    created_at: datetime
    updated_at: datetime
    version_no: int


class EvaluationCaseOutput(APIModel):
    case_id: str | None = None
    external_id: str | None = Field(default=None, max_length=160)
    output: str | None = Field(default=None, max_length=100_000)
    conclusions: list[str] = Field(default_factory=list, max_length=64)
    citations: list[str] = Field(default_factory=list, max_length=64)
    selected_template: str | None = Field(default=None, max_length=120)
    policy_result: Literal["allow", "deny", "requires_approval"] | None = None
    evidence_fields: dict[str, Any] = Field(default_factory=dict)
    tools_requested: list[str] = Field(default_factory=list, max_length=64)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0)
    latency_ms: int = Field(default=0, ge=0)
    structured_output: bool = True
    error: str | None = Field(default=None, max_length=4000)
    model_invocation_id: str | None = None
    judge: dict[str, Any] | None = None


class EvaluationRunVariantCreate(APIModel):
    name: str = Field(min_length=1, max_length=120)
    role: Literal["baseline", "candidate"]
    model_configuration: dict[str, Any] = Field(default_factory=dict)
    prompt_template: dict[str, Any] = Field(default_factory=dict)
    agent_definition: dict[str, Any] = Field(default_factory=dict)
    skill_definition: dict[str, Any] = Field(default_factory=dict)
    knowledge_package: dict[str, Any] = Field(default_factory=dict)
    retrieval_configuration: dict[str, Any] = Field(default_factory=dict)
    policy_version: dict[str, Any] = Field(default_factory=dict)
    workflow_definition: dict[str, Any] = Field(default_factory=dict)
    metric_definition_version: str = Field(default="p11-default-metrics-v1", max_length=120)
    case_outputs: list[EvaluationCaseOutput] = Field(default_factory=list, max_length=1000)


class EvaluationRunCreate(APIModel):
    suite_id: str
    dataset_id: str
    project_id: str = Field(default="default", min_length=1, max_length=120)
    evaluation_type: EvaluationType = "deterministic_offline"
    variants: list[EvaluationRunVariantCreate] = Field(min_length=2, max_length=8)
    gate_config: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def has_baseline_and_candidate(self) -> EvaluationRunCreate:
        roles = {variant.role for variant in self.variants}
        if not {"baseline", "candidate"} <= roles:
            raise ValueError("evaluation run requires baseline and candidate variants")
        return self


class ConfigurationSnapshotResponse(APIModel):
    id: str
    run_id: str
    variant_id: str
    tenant_id: str
    project_id: str
    snapshot: dict[str, Any]
    snapshot_hash: str
    created_at: datetime


class EvaluationRunVariantResponse(APIModel):
    id: str
    run_id: str
    tenant_id: str
    project_id: str
    name: str
    role: Literal["baseline", "candidate"]
    configuration_snapshot_id: str
    configuration_hash: str
    status: Literal["PENDING", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED"]
    created_at: datetime
    updated_at: datetime
    version_no: int


class EvaluationRunResponse(APIModel):
    id: str
    suite_id: str
    dataset_id: str
    tenant_id: str
    project_id: str
    evaluation_type: EvaluationType
    status: EvaluationStatus
    gate_status: Literal["PENDING", "PASSED", "FAILED", "NOT_EVALUATED"]
    baseline_variant_id: str | None
    candidate_variant_id: str | None
    config_hash: str
    created_by: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime
    version_no: int
    variants: list[EvaluationRunVariantResponse] = Field(default_factory=list)


class EvaluationResultResponse(APIModel):
    id: str
    run_id: str
    variant_id: str
    case_id: str
    tenant_id: str
    project_id: str
    status: Literal["PASSED", "FAILED", "ERROR", "GROUND_TRUTH_MISSING", "INCONCLUSIVE"]
    output: dict[str, Any]
    scores: dict[str, Any]
    failure_reasons: list[str]
    model_invocation_id: str | None
    judge: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime
    version_no: int


class MetricDefinitionResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    name: str
    category: Literal["quality", "security", "cost", "latency", "stability"]
    direction: Literal["higher_is_better", "lower_is_better"]
    definition: dict[str, Any]
    version: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    version_no: int


class MetricResultResponse(APIModel):
    id: str
    run_id: str
    variant_id: str
    metric_definition_id: str
    tenant_id: str
    project_id: str
    metric_name: str
    category: str
    value: float
    unit: str
    threshold: float | None
    passed: bool | None
    details: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    version_no: int


class EvaluationFailureResponse(APIModel):
    result_id: str
    run_id: str
    variant_id: str
    case_id: str
    external_id: str
    status: str
    failure_reasons: list[str]
    scores: dict[str, Any]


class EvaluationComparisonCreate(APIModel):
    run_id: str
    baseline_variant_id: str
    candidate_variant_id: str
    gate_config: dict[str, Any] = Field(default_factory=dict)


class EvaluationComparisonResponse(APIModel):
    id: str
    run_id: str
    suite_id: str
    dataset_id: str
    tenant_id: str
    project_id: str
    baseline_variant_id: str
    candidate_variant_id: str
    improved_metrics: list[str]
    regressed_metrics: list[str]
    new_failures: list[str]
    resolved_failures: list[str]
    cost_change: float
    latency_change: float
    security_gate_status: Literal["PASSED", "FAILED"]
    gate_status: Literal["PASSED", "FAILED"]
    failed_gates: list[str]
    details: dict[str, Any]
    created_by: str
    created_at: datetime
    updated_at: datetime
    version_no: int


class EvaluationReviewCreate(APIModel):
    decision: Literal["ACCEPTED", "REJECTED", "CHANGES_REQUESTED"]
    blind: bool = True
    comments: str = Field(min_length=3, max_length=4000)
    annotations: dict[str, Any] = Field(default_factory=dict)


class EvaluationReviewResponse(APIModel):
    id: str
    run_id: str
    tenant_id: str
    project_id: str
    decision: Literal["ACCEPTED", "REJECTED", "CHANGES_REQUESTED"]
    blind: bool
    comments: str
    annotations: dict[str, Any]
    reviewed_by: str
    reviewed_at: datetime
    created_at: datetime
    updated_at: datetime
    version_no: int


class PromotionDecisionCreate(APIModel):
    decision: Literal["APPROVED", "REJECTED", "PROMOTED", "ROLLED_BACK"]
    reason: str = Field(min_length=3, max_length=4000)
    expected_version: int = Field(ge=1)
    target_environment: str = Field(default="production", min_length=1, max_length=120)


class PromotionDecisionResponse(APIModel):
    id: str
    run_id: str
    comparison_id: str | None
    tenant_id: str
    project_id: str
    decision: Literal["APPROVED", "REJECTED", "PROMOTED", "ROLLED_BACK"]
    reason: str
    target_environment: str
    decided_by: str
    decided_at: datetime
    created_at: datetime
    updated_at: datetime
    version_no: int


class EvidenceConsistencyCheckRequest(APIModel):
    repair: bool = False
    repair_action: Literal["none", "recompute_metadata_hash"] = "none"


class EvidenceConsistencyReportResponse(APIModel):
    id: str
    tenant_id: str
    status: Literal["healthy", "inconsistent"]
    summary: dict[str, int]
    findings: list[dict[str, Any]]
    repair_action: str
    created_at: str


class SystemResilienceResponse(APIModel):
    version: str
    mode: dict[str, Any]
    service_instances: list[dict[str, Any]]
    workers: list[dict[str, Any]]
    queue: dict[str, Any]
    fairness: dict[str, Any]
    capacity: dict[str, Any]
    database: dict[str, Any]
    nats: dict[str, Any]
    evidence_consistency: dict[str, Any] | None
    backup: dict[str, Any]
    disaster_recovery: dict[str, Any]
    chaos: dict[str, Any]
    boundaries: list[str]


class EvaluationDatasetDetailResponse(EvaluationDatasetResponse):
    cases: list[EvaluationCaseResponse] = Field(default_factory=list)


class EvaluationRunDetailResponse(EvaluationRunResponse):
    results: list[EvaluationResultResponse] = Field(default_factory=list)
    metrics: list[MetricResultResponse] = Field(default_factory=list)
    comparisons: list[EvaluationComparisonResponse] = Field(default_factory=list)
    reviews: list[EvaluationReviewResponse] = Field(default_factory=list)
    promotion_decisions: list[PromotionDecisionResponse] = Field(default_factory=list)


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


ReleaseEnvironment = Literal["development", "integration", "staging", "production"]
ReleaseGateStatus = Literal["passed", "failed", "warning"]


class SBOMDocumentCreate(APIModel):
    format: str = Field(min_length=2, max_length=80)
    generator: str = Field(min_length=2, max_length=160)
    generated_at: datetime
    artifact_digest: str = Field(min_length=16, max_length=256)
    document_digest: str = Field(min_length=16, max_length=256)
    component_count: int = Field(default=0, ge=0)
    license_summary: dict[str, Any] = Field(default_factory=dict)
    vulnerability_summary: dict[str, Any] = Field(default_factory=dict)
    document_ref: str = Field(default="", max_length=2048)


class ProvenanceStatementCreate(APIModel):
    subject_digest: str = Field(min_length=16, max_length=256)
    source_repository: str = Field(min_length=1, max_length=500)
    source_commit: str = Field(min_length=7, max_length=80)
    builder_workflow: str = Field(min_length=1, max_length=500)
    statement_digest: str = Field(min_length=16, max_length=256)
    predicate_type: str = Field(min_length=1, max_length=200)
    verified: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class SignatureRecordCreate(APIModel):
    signature_digest: str = Field(min_length=16, max_length=256)
    signature_identity: str = Field(min_length=1, max_length=500)
    certificate_issuer: str = Field(min_length=1, max_length=500)
    verified: bool = False
    verification_error: str = Field(default="", max_length=1000)


class SecurityScanResultCreate(APIModel):
    scanner: str = Field(min_length=1, max_length=160)
    severity_summary: dict[str, Any] = Field(default_factory=dict)
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    unresolved_critical: bool = False
    scan_digest: str = Field(min_length=16, max_length=256)


class LicenseScanResultCreate(APIModel):
    scanner: str = Field(min_length=1, max_length=160)
    license_summary: dict[str, Any] = Field(default_factory=dict)
    prohibited_licenses: list[str] = Field(default_factory=list, max_length=256)
    passed: bool = False
    scan_digest: str = Field(min_length=16, max_length=256)


class ReleaseArtifactCreate(APIModel):
    tenant_id: str = Field(default="system", min_length=1, max_length=80)
    project_id: str = Field(default="default", min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=200)
    artifact_type: Literal[
        "container", "helm_chart", "python_package", "node_package", "release_package"
    ]
    digest: str = Field(min_length=16, max_length=256)
    repository: str = Field(default="", max_length=500)
    source_commit: str = Field(min_length=7, max_length=80)
    metadata: dict[str, Any] = Field(default_factory=dict)
    sbom: SBOMDocumentCreate | None = None
    provenance: ProvenanceStatementCreate | None = None
    signature: SignatureRecordCreate | None = None
    security_scan: SecurityScanResultCreate | None = None
    license_scan: LicenseScanResultCreate | None = None

    @model_validator(mode="after")
    def immutable_digest_identity(self) -> ReleaseArtifactCreate:
        lowered = self.digest.lower()
        mutable_markers = (":latest", ":main", ":production", ":prod")
        if self.artifact_type == "container":
            if "@sha256:" not in lowered:
                raise ValueError("container artifact identity must use repo@sha256 digest")
            image_ref = lowered.split("@sha256:", 1)[0]
            if image_ref.endswith(mutable_markers):
                raise ValueError("mutable tags cannot be used as deployment identity")
        elif not (lowered.startswith("sha256:") or "@sha256:" in lowered):
            raise ValueError("artifact digest must be sha256 based")
        return self


class ReleaseArtifactResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    name: str
    artifact_type: str
    digest: str
    repository: str
    source_commit: str
    metadata: dict[str, Any]
    created_by: str
    created_at: str
    updated_at: str
    version: int


class SBOMDocumentResponse(APIModel):
    id: str
    artifact_id: str
    format: str
    generator: str
    generated_at: str
    artifact_digest: str
    document_digest: str
    component_count: int
    license_summary: dict[str, Any]
    vulnerability_summary: dict[str, Any]
    document_ref: str
    created_at: str
    version: int


class ProvenanceStatementResponse(APIModel):
    id: str
    artifact_id: str
    subject_digest: str
    source_repository: str
    source_commit: str
    builder_workflow: str
    statement_digest: str
    predicate_type: str
    verified: bool
    metadata: dict[str, Any]
    created_at: str
    version: int


class SignatureRecordResponse(APIModel):
    id: str
    artifact_id: str
    signature_digest: str
    signature_identity: str
    certificate_issuer: str
    verified: bool
    verification_error: str
    created_at: str
    version: int


class SecurityScanResultResponse(APIModel):
    id: str
    artifact_id: str
    scanner: str
    severity_summary: dict[str, Any]
    critical_count: int
    high_count: int
    unresolved_critical: bool
    scan_digest: str
    created_at: str
    version: int


class LicenseScanResultResponse(APIModel):
    id: str
    artifact_id: str
    scanner: str
    license_summary: dict[str, Any]
    prohibited_licenses: list[str]
    passed: bool
    scan_digest: str
    created_at: str
    version: int


class ReleaseArtifactDetailResponse(ReleaseArtifactResponse):
    sbom_documents: list[SBOMDocumentResponse]
    provenance_statements: list[ProvenanceStatementResponse]
    signature_records: list[SignatureRecordResponse]
    security_scans: list[SecurityScanResultResponse]
    license_scans: list[LicenseScanResultResponse]


class ReleaseCandidateCreate(APIModel):
    tenant_id: str = Field(default="system", min_length=1, max_length=80)
    project_id: str = Field(default="default", min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=200)
    artifact_id: str = Field(min_length=1, max_length=120)
    configuration_hash: str = Field(min_length=16, max_length=128)
    migration_set: list[str] = Field(default_factory=list, max_length=128)
    helm_chart_digest: str = Field(min_length=16, max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReleaseCandidateResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    name: str
    artifact_id: str
    source_commit: str
    image_digest: str
    sbom_digest: str
    provenance_digest: str
    signature_digest: str
    configuration_hash: str
    migration_set: list[str]
    helm_chart_digest: str
    status: str
    freeze_hash: str
    metadata: dict[str, Any]
    created_by: str
    created_at: str
    updated_at: str
    version: int


class ReleaseGateEvaluationRequest(APIModel):
    environment: ReleaseEnvironment = "staging"


class ReleaseGateResultResponse(APIModel):
    id: str
    candidate_id: str
    gate_id: str
    environment: ReleaseEnvironment
    status: ReleaseGateStatus
    reason: str
    evidence: dict[str, Any]
    evaluated_by: str
    policy_decision_id: str | None
    created_at: str
    version: int


class ReleaseApprovalCreate(APIModel):
    environment: ReleaseEnvironment
    decision: Literal["approved", "rejected"] = "approved"
    reason: str = Field(default="", max_length=1000)
    expected_version: int | None = Field(default=None, ge=1)


class ReleaseApprovalResponse(APIModel):
    id: str
    candidate_id: str
    environment: ReleaseEnvironment
    decision: str
    reason: str
    approved_by: str
    created_at: str
    version: int


class ReleaseExceptionCreate(APIModel):
    gate_id: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=3, max_length=2000)
    risk: Literal["low", "medium", "high", "critical"]
    scope: str = Field(min_length=1, max_length=500)
    expires_at: datetime
    compensating_controls: list[str] = Field(default_factory=list, min_length=1, max_length=32)
    approve: bool = False


class ReleaseExceptionResponse(APIModel):
    id: str
    candidate_id: str
    gate_id: str
    reason: str
    risk: str
    scope: str
    requested_by: str
    approved_by: str | None
    expires_at: str
    compensating_controls: list[str]
    status: str
    created_at: str
    updated_at: str
    version: int


class EnvironmentPromotionCreate(APIModel):
    environment: ReleaseEnvironment
    canary_percentage: int = Field(default=100, ge=0, le=100)
    health: dict[str, Any] = Field(default_factory=dict)
    expected_version: int | None = Field(default=None, ge=1)


class EnvironmentPromotionResponse(APIModel):
    id: str
    candidate_id: str
    environment: ReleaseEnvironment
    status: str
    promoted_by: str
    policy_decision_id: str | None
    created_at: str
    updated_at: str
    version: int


class DeploymentRecordResponse(APIModel):
    id: str
    promotion_id: str
    candidate_id: str
    environment: ReleaseEnvironment
    image_digest: str
    canary_percentage: int
    status: str
    health: dict[str, Any]
    created_at: str
    updated_at: str
    version: int


class EnvironmentPromotionResultResponse(EnvironmentPromotionResponse):
    deployment: DeploymentRecordResponse


class RollbackCreate(APIModel):
    reason: str = Field(min_length=3, max_length=2000)
    approved_by: str | None = Field(default=None, max_length=120)


class RollbackRecordResponse(APIModel):
    id: str
    deployment_id: str
    candidate_id: str
    environment: ReleaseEnvironment
    reason: str
    requested_by: str
    approved_by: str | None
    status: str
    created_at: str
    updated_at: str
    version: int


class DriftDetectionResultResponse(APIModel):
    id: str
    deployment_id: str
    status: str
    drift_types: list[str]
    expected: dict[str, Any]
    actual: dict[str, Any]
    reviewed_by: str | None
    created_at: str
    version: int


class CompliancePackageResponse(APIModel):
    id: str
    candidate_id: str
    package_digest: str
    contents: dict[str, Any]
    generated_by: str
    created_at: str
    version: int


class ReleaseCandidateDetailResponse(ReleaseCandidateResponse):
    artifact: ReleaseArtifactDetailResponse
    gates: list[ReleaseGateResultResponse]
    approvals: list[ReleaseApprovalResponse]
    exceptions: list[ReleaseExceptionResponse]
    promotions: list[EnvironmentPromotionResponse]
    deployments: list[DeploymentRecordResponse]


class RequirementTraceabilityItem(APIModel):
    requirement_id: str
    requirement_description: str
    implementation_status: Literal[
        "IMPLEMENTED", "PARTIALLY_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_APPLICABLE", "BLOCKED"
    ]
    backend_modules: list[str]
    frontend_routes: list[str]
    api_operations: list[str]
    database_migrations: list[str]
    policy_actions: list[str]
    tests: list[str]
    acceptance_scripts: list[str]
    documents: list[str]
    known_limitations: list[str]
    runtime_evidence: dict[str, Any]


class ProductionGateResponse(APIModel):
    gate_id: str
    status: Literal["passed", "failed", "warning", "blocked"]
    critical: bool
    evidence_kind: Literal[
        "static", "deterministic", "runtime", "manual", "contract", "release_artifact"
    ]
    reason: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class AcceptanceStatusResponse(APIModel):
    version: str
    valid: bool
    production_ready: bool
    runtime: bool
    runtime_not_claimed: bool
    critical_gates: list[ProductionGateResponse]
    failed_critical_gates: list[str]
    supported_upgrade_paths: list[str]
    unsupported_upgrade_paths: list[str]
    data_governance: dict[str, Any]
    secret_lifecycle: dict[str, Any]
    known_limitations: list[str]
    evaluated_at: str


class ProductionReadinessResponse(APIModel):
    version: str
    production_ready: bool
    valid: bool
    runtime: bool
    runtime_not_claimed: bool
    critical_gates: list[ProductionGateResponse]
    failed_critical_gates: list[str]
    policy_decision_id: str
    supported_upgrade_paths: list[str]
    unsupported_upgrade_paths: list[str]
    known_limitations: list[str]
    evaluated_at: str


class AcceptanceRunCreate(APIModel):
    tenant_id: str = Field(default="system", min_length=1, max_length=120)
    project_id: str = Field(default="project-alpha", min_length=1, max_length=120)
    scenario_id: str = Field(
        default="p14-final-enterprise-acceptance", min_length=3, max_length=120
    )
    trace_id: str = Field(default_factory=lambda: uuid.uuid4().hex, min_length=16, max_length=64)
    runtime_evidence: dict[str, Any] = Field(default_factory=dict)


class AcceptanceRunResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    scenario_id: str
    status: str
    valid: bool
    production_ready: bool
    runtime: bool
    runtime_not_claimed: bool
    trace_id: str
    policy_decision_id: str
    result: dict[str, Any]
    created_by: str
    created_at: str
    updated_at: str
    version: int


class DeliveryPackageCreate(APIModel):
    tenant_id: str = Field(default="system", min_length=1, max_length=120)
    project_id: str = Field(default="project-alpha", min_length=1, max_length=120)
    package_type: Literal["candidate", "formal"] = "candidate"


class DeliveryPackageResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    package_type: Literal["candidate", "formal"]
    formal: bool
    status: str
    root_path: str
    package_digest: str
    manifest: dict[str, Any]
    policy_decision_id: str
    generated_by: str
    created_at: str
    updated_at: str
    version: int


class ComplianceControlResponse(APIModel):
    framework: str
    control_id: str
    implementation: str
    evidence: list[str]
    owner: str
    test: str
    status: str
    gap: str
    exception: str
    last_reviewed_at: str
    certification_claim: bool
    disclaimer: str


class ComplianceEvidencePackageCreate(APIModel):
    tenant_id: str = Field(default="system", min_length=1, max_length=120)
    project_id: str = Field(default="project-alpha", min_length=1, max_length=120)
    frameworks: list[str] = Field(default_factory=list, max_length=16)


class ComplianceEvidencePackageResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    package_digest: str
    controls: list[ComplianceControlResponse]
    certification_claim: bool
    disclaimer: str
    policy_decision_id: str
    generated_by: str
    created_at: str
    updated_at: str
    version: int


class DataExportCreate(APIModel):
    tenant_id: str = Field(default="system", min_length=1, max_length=120)
    project_id: str = Field(default="project-alpha", min_length=1, max_length=120)
    format: Literal["json"] = "json"


class DataExportResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    export_type: str
    status: str
    manifest: dict[str, Any]
    redacted: bool
    secret_count: int
    policy_decision_id: str
    requested_by: str
    created_at: str
    updated_at: str
    version: int


class DataDeletionRequestCreate(APIModel):
    tenant_id: str = Field(default="system", min_length=1, max_length=120)
    project_id: str = Field(default="project-alpha", min_length=1, max_length=120)
    target_type: Literal["tenant", "project", "case", "report", "validation_metadata"]
    target_id: str = Field(min_length=1, max_length=200)
    dry_run: bool = True
    reason: str = Field(min_length=3, max_length=1000)


class DataDeletionRequestResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    target_type: str
    target_id: str
    dry_run: bool
    status: str
    scope_preview: dict[str, Any]
    deletion_certificate: dict[str, Any]
    policy_decision_id: str
    requested_by: str
    approved_by: str | None
    created_at: str
    updated_at: str
    version: int


class LegalHoldCreate(APIModel):
    tenant_id: str = Field(default="system", min_length=1, max_length=120)
    project_id: str = Field(default="project-alpha", min_length=1, max_length=120)
    hold_type: Literal["litigation", "incident", "regulatory", "customer_request"] = "incident"
    reason: str = Field(min_length=3, max_length=1000)
    scope: dict[str, Any] = Field(default_factory=dict)


class LegalHoldResponse(APIModel):
    id: str
    tenant_id: str
    project_id: str
    hold_type: str
    status: str
    reason: str
    scope: dict[str, Any]
    policy_decision_id: str
    created_by: str
    released_by: str | None
    created_at: str
    updated_at: str
    version: int


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
        "evaluation.suite.create",
        "evaluation.dataset.manage",
        "evaluation.run",
        "evaluation.cancel",
        "evaluation.review",
        "evaluation.compare",
        "evaluation.promote",
        "evaluation.rollback",
        "metric.definition.manage",
        "release.artifact.register",
        "release.candidate.create",
        "release.gate.evaluate",
        "release.exception.request",
        "release.exception.approve",
        "release.approve",
        "release.promote.development",
        "release.promote.integration",
        "release.promote.staging",
        "release.promote.production",
        "release.rollback",
        "release.drift.review",
        "release.compliance.generate",
        "acceptance.run",
        "acceptance.review",
        "delivery.generate",
        "delivery.download",
        "compliance.map",
        "compliance.generate",
        "data.export",
        "data.delete.request",
        "data.delete.approve",
        "legal-hold.create",
        "legal-hold.release",
        "secret.rotate",
        "production-readiness.review",
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
