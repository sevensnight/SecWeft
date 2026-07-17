import { createVulnLabClient } from '@vulnlab/api-client';
import type {
  ValidationExecution,
  ValidationExecutionEvent,
  ValidationExecutionEvidence,
  ValidationExecutionReview,
  ValidationTemplate,
} from '@vulnlab/shared-types';

import { useSessionStore } from '../stores/session';

class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(`${status}: ${message}`);
    this.name = 'ApiError';
  }
}

const apiClient = createVulnLabClient({
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

export async function listValidationTemplates(): Promise<ValidationTemplate[]> {
  const { data, error, response } = await apiClient.GET('/validation-templates');
  return requireData(data, error, response, 'Unable to read validation templates');
}

export async function listValidationExecutions(
  limit = 100,
  taskId?: string | null,
): Promise<ValidationExecution[]> {
  const { data, error, response } = await apiClient.GET('/validation-executions', {
    params: { query: { limit, task_id: taskId ?? null } },
  });
  return requireData(data, error, response, 'Unable to read validation executions');
}

export async function createValidationExecution(
  planId: string,
  templateId = 'http.response',
): Promise<ValidationExecution> {
  const { data, error, response } = await apiClient.POST('/validation-plans/{plan_id}/executions', {
    params: {
      path: { plan_id: planId },
      header: { 'Idempotency-Key': idempotencyKey('validation-execution') },
    },
    body: { template_id: templateId },
  });
  return requireData(data, error, response, 'Unable to queue validation execution');
}

export async function cancelValidationExecution(
  executionId: string,
  reason = 'Cancelled from validation console',
): Promise<ValidationExecution> {
  const { data, error, response } = await apiClient.POST('/validation-executions/{execution_id}/cancel', {
    params: {
      path: { execution_id: executionId },
      header: { 'Idempotency-Key': idempotencyKey('validation-cancel') },
    },
    body: { reason },
  });
  return requireData(data, error, response, 'Unable to cancel validation execution');
}

export async function retryValidationExecution(executionId: string): Promise<ValidationExecution> {
  const { data, error, response } = await apiClient.POST('/validation-executions/{execution_id}/retry', {
    params: {
      path: { execution_id: executionId },
      header: { 'Idempotency-Key': idempotencyKey('validation-retry') },
    },
  });
  return requireData(data, error, response, 'Unable to retry validation execution');
}

export async function listValidationExecutionEvents(
  executionId: string,
  afterId = 0,
): Promise<ValidationExecutionEvent[]> {
  const { data, error, response } = await apiClient.GET('/validation-executions/{execution_id}/events', {
    params: { path: { execution_id: executionId }, query: { after_id: afterId, limit: 500 } },
  });
  return requireData(data, error, response, 'Unable to read validation execution events');
}

export async function listValidationExecutionEvidence(
  executionId: string,
): Promise<ValidationExecutionEvidence[]> {
  const { data, error, response } = await apiClient.GET('/validation-executions/{execution_id}/evidence', {
    params: { path: { execution_id: executionId }, query: { limit: 200 } },
  });
  return requireData(data, error, response, 'Unable to read validation execution evidence');
}

export async function reviewValidationExecution(
  executionId: string,
  value: ValidationExecutionReview,
): Promise<ValidationExecution> {
  const { data, error, response } = await apiClient.POST('/validation-executions/{execution_id}/reviews', {
    params: {
      path: { execution_id: executionId },
      header: { 'Idempotency-Key': idempotencyKey('validation-execution-review') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to review validation execution');
}
