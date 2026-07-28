import { createVulnLabClient } from '@vulnlab/api-client';
import type {
  AgentDefinition,
  AuditEvent,
  EnterpriseRole,
  EnterpriseSession,
  EnterpriseUser,
  EvidenceConsistencyCheck,
  EvidenceConsistencyReport,
  EvidenceItem,
  ModelCatalogItem,
  ModelInvocation,
  ModelProvider,
  ModelProviderHealth,
  PolicyDecision,
  PolicyEvaluationRequest,
  Project,
  RAGDocument,
  RAGDocumentCreate,
  RAGSearchRequest,
  RAGSearchResponse,
  SkillDefinition,
  SystemRequirements,
  SystemResilience,
  Task,
  TaskEvent,
  TaskExecution,
  Tenant,
  ValidationPlan,
  ValidationPlanCreate,
  ValidationPlanReview,
  WorkflowDefinition,
} from '@vulnlab/shared-types';

import { useSessionStore } from '../stores/session';

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(`${status}: ${message}`);
    this.name = 'ApiError';
  }
}

export const apiClient = createVulnLabClient({
  getAccessToken: () => useSessionStore.getState().accessToken,
  getApiKey: () => useSessionStore.getState().apiKey,
  getProjectId: () => useSessionStore.getState().projectId,
});

function errorMessage(error: unknown, fallback: string): string {
  if (typeof error === 'object' && error !== null && 'detail' in error) {
    const detail = (error as { detail?: unknown }).detail;
    if (typeof detail === 'string') return detail;
  }
  return fallback;
}

function requireData<T>(
  data: T | undefined,
  error: unknown,
  response: Response,
  fallback: string,
): T {
  if (data === undefined) throw new ApiError(errorMessage(error, fallback), response.status);
  return data;
}

function idempotencyKey(prefix: string) {
  return `${prefix}-${crypto.randomUUID()}`;
}

export async function getSystemRequirements(): Promise<SystemRequirements> {
  const { data, error, response } = await apiClient.GET('/system/requirements');
  return requireData(data, error, response, '无法读取系统能力');
}

export async function getSystemResilience(): Promise<SystemResilience> {
  const { data, error, response } = await apiClient.GET('/system/resilience');
  return requireData(data, error, response, 'Unable to read resilience status');
}

export async function runEvidenceConsistencyCheck(
  value: EvidenceConsistencyCheck = { repair: false, repair_action: 'none' },
): Promise<EvidenceConsistencyReport> {
  const { data, error, response } = await apiClient.POST(
    '/system/resilience/evidence-consistency/check',
    {
      params: { header: { 'Idempotency-Key': idempotencyKey('evidence-consistency') } },
      body: value,
    },
  );
  return requireData(data, error, response, 'Unable to run evidence consistency check');
}

export async function listTasks(limit = 500): Promise<Task[]> {
  const { data, error, response } = await apiClient.GET('/tasks', { params: { query: { limit } } });
  return requireData(data, error, response, '无法读取任务列表');
}

export async function getTask(taskId: string): Promise<Task> {
  const { data, error, response } = await apiClient.GET('/tasks/{task_id}', {
    params: { path: { task_id: taskId } },
  });
  return requireData(data, error, response, '无法读取任务');
}

export async function listTaskEvents(taskId: string): Promise<TaskEvent[]> {
  const { data, error, response } = await apiClient.GET('/tasks/{task_id}/events', {
    params: { path: { task_id: taskId } },
  });
  return requireData(data, error, response, '无法读取任务事件');
}

export async function listTaskExecutions(taskId: string): Promise<TaskExecution[]> {
  const { data, error, response } = await apiClient.GET('/tasks/{task_id}/executions', {
    params: { path: { task_id: taskId } },
  });
  return requireData(data, error, response, '无法读取任务执行记录');
}

export async function listTaskEvidence(taskId: string, limit = 100): Promise<EvidenceItem[]> {
  const { data, error, response } = await apiClient.GET('/tasks/{task_id}/evidence', {
    params: { path: { task_id: taskId }, query: { limit } },
  });
  return requireData(data, error, response, '无法读取任务证据');
}

export async function getEnterpriseSession(): Promise<EnterpriseSession> {
  const { data, error, response } = await apiClient.GET('/session');
  return requireData(data, error, response, '无法读取当前会话');
}

export async function getCurrentTenant(): Promise<Tenant> {
  const { data, error, response } = await apiClient.GET('/tenants/current');
  return requireData(data, error, response, '无法读取当前租户');
}

export async function listProjects(): Promise<Project[]> {
  const { data, error, response } = await apiClient.GET('/projects', {
    params: { query: { page_size: 100 } },
  });
  return requireData(data, error, response, '无法读取项目列表').items;
}

export async function listEnterpriseUsers(): Promise<EnterpriseUser[]> {
  const { data, error, response } = await apiClient.GET('/iam/users', {
    params: { query: { page_size: 100 } },
  });
  return requireData(data, error, response, '无法读取租户用户').items;
}

export async function listEnterpriseRoles(): Promise<EnterpriseRole[]> {
  const { data, error, response } = await apiClient.GET('/iam/roles', {
    params: { query: { page_size: 100 } },
  });
  return requireData(data, error, response, '无法读取角色目录').items;
}

export async function listAuditEvents(pageSize = 100): Promise<AuditEvent[]> {
  const { data, error, response } = await apiClient.GET('/audit/events', {
    params: { query: { page_size: pageSize } },
  });
  return requireData(data, error, response, '无法读取审计事件').items;
}

export async function listAgents(): Promise<AgentDefinition[]> {
  const { data, error, response } = await apiClient.GET('/agents');
  return requireData(data, error, response, '无法读取 Agent 定义');
}

export async function listWorkflows(): Promise<WorkflowDefinition[]> {
  const { data, error, response } = await apiClient.GET('/workflows');
  return requireData(data, error, response, '无法读取工作流定义');
}

export async function listSkills(): Promise<SkillDefinition[]> {
  const { data, error, response } = await apiClient.GET('/skills');
  return requireData(data, error, response, '无法读取 Skill 定义');
}

export async function listModelProviders(): Promise<ModelProvider[]> {
  const { data, error, response } = await apiClient.GET('/providers');
  return requireData(data, error, response, '无法读取模型供应商');
}

export async function listModelProviderHealth(): Promise<ModelProviderHealth[]> {
  const { data, error, response } = await apiClient.GET('/providers/health');
  return requireData(data, error, response, '无法读取模型健康状态');
}

export async function listModelCatalog(): Promise<ModelCatalogItem[]> {
  const { data, error, response } = await apiClient.GET('/models/catalog');
  return requireData(data, error, response, '无法读取模型目录');
}

export async function listModelInvocations(limit = 100): Promise<ModelInvocation[]> {
  const { data, error, response } = await apiClient.GET('/models/invocations', {
    params: { query: { limit } },
  });
  return requireData(data, error, response, '无法读取模型调用记录');
}

export async function ingestRagDocument(value: RAGDocumentCreate): Promise<RAGDocument> {
  const { data, error, response } = await apiClient.POST('/rag/documents', {
    params: { header: { 'Idempotency-Key': idempotencyKey('rag-document') } },
    body: value,
  });
  return requireData(data, error, response, '无法导入知识文档');
}

export async function searchRagDocuments(value: RAGSearchRequest): Promise<RAGSearchResponse> {
  const { data, error, response } = await apiClient.POST('/rag/search', {
    params: { header: { 'Idempotency-Key': idempotencyKey('rag-search') } },
    body: value,
  });
  return requireData(data, error, response, '无法检索知识库');
}

export async function evaluatePolicy(value: PolicyEvaluationRequest): Promise<PolicyDecision> {
  const { data, error, response } = await apiClient.POST('/policies/evaluate', {
    params: { header: { 'Idempotency-Key': idempotencyKey('policy-evaluate') } },
    body: value,
  });
  return requireData(data, error, response, '无法评估策略');
}

export async function listTaskValidationPlans(
  taskId: string,
  limit = 100,
): Promise<ValidationPlan[]> {
  const { data, error, response } = await apiClient.GET('/tasks/{task_id}/validation-plans', {
    params: { path: { task_id: taskId }, query: { limit } },
  });
  return requireData(data, error, response, '无法读取验证计划');
}

export async function createTaskValidationPlan(
  taskId: string,
  value: ValidationPlanCreate,
): Promise<ValidationPlan> {
  const { data, error, response } = await apiClient.POST('/tasks/{task_id}/validation-plans', {
    params: {
      path: { task_id: taskId },
      header: { 'Idempotency-Key': idempotencyKey('validation-plan') },
    },
    body: value,
  });
  return requireData(data, error, response, '无法创建验证计划');
}

export async function submitValidationPlan(planId: string): Promise<ValidationPlan> {
  const { data, error, response } = await apiClient.POST('/validation-plans/{plan_id}/submit', {
    params: {
      path: { plan_id: planId },
      header: { 'Idempotency-Key': idempotencyKey('validation-submit') },
    },
  });
  return requireData(data, error, response, '无法提交验证计划');
}

export async function reviewValidationPlan(
  planId: string,
  value: ValidationPlanReview,
): Promise<ValidationPlan> {
  const { data, error, response } = await apiClient.POST('/validation-plans/{plan_id}/review', {
    params: {
      path: { plan_id: planId },
      header: { 'Idempotency-Key': idempotencyKey('validation-review') },
    },
    body: value,
  });
  return requireData(data, error, response, '无法审核验证计划');
}
