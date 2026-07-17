import { createVulnLabClient } from '@vulnlab/api-client';
import type {
  AuditEvent,
  EnterpriseRole,
  EnterpriseSession,
  EnterpriseUser,
  Project,
  SystemRequirements,
  Task,
  TaskEvent,
  Tenant,
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

export async function getSystemRequirements(): Promise<SystemRequirements> {
  const { data, error, response } = await apiClient.GET('/system/requirements');
  if (!data) throw new ApiError(errorMessage(error, '无法读取系统能力'), response.status);
  return data;
}

export async function listTasks(limit = 500): Promise<Task[]> {
  const { data, error, response } = await apiClient.GET('/tasks', { params: { query: { limit } } });
  if (!data) throw new ApiError(errorMessage(error, '无法读取任务列表'), response.status);
  return data;
}

export async function getTask(taskId: string): Promise<Task> {
  const { data, error, response } = await apiClient.GET('/tasks/{task_id}', {
    params: { path: { task_id: taskId } },
  });
  if (!data) throw new ApiError(errorMessage(error, '无法读取任务'), response.status);
  return data;
}

export async function listTaskEvents(taskId: string): Promise<TaskEvent[]> {
  const { data, error, response } = await apiClient.GET('/tasks/{task_id}/events', {
    params: { path: { task_id: taskId } },
  });
  if (!data) throw new ApiError(errorMessage(error, '无法读取任务事件'), response.status);
  return data;
}

export async function getEnterpriseSession(): Promise<EnterpriseSession> {
  const { data, error, response } = await apiClient.GET('/session');
  if (!data) throw new ApiError(errorMessage(error, '无法读取企业会话'), response.status);
  return data;
}

export async function getCurrentTenant(): Promise<Tenant> {
  const { data, error, response } = await apiClient.GET('/tenants/current');
  if (!data) throw new ApiError(errorMessage(error, '无法读取当前租户'), response.status);
  return data;
}

export async function listProjects(): Promise<Project[]> {
  const { data, error, response } = await apiClient.GET('/projects', {
    params: { query: { page_size: 100 } },
  });
  if (!data) throw new ApiError(errorMessage(error, '无法读取项目列表'), response.status);
  return data.items;
}

export async function listEnterpriseUsers(): Promise<EnterpriseUser[]> {
  const { data, error, response } = await apiClient.GET('/iam/users', {
    params: { query: { page_size: 100 } },
  });
  if (!data) throw new ApiError(errorMessage(error, '无法读取租户用户'), response.status);
  return data.items;
}

export async function listEnterpriseRoles(): Promise<EnterpriseRole[]> {
  const { data, error, response } = await apiClient.GET('/iam/roles', {
    params: { query: { page_size: 100 } },
  });
  if (!data) throw new ApiError(errorMessage(error, '无法读取角色目录'), response.status);
  return data.items;
}

export async function listAuditEvents(): Promise<AuditEvent[]> {
  const { data, error, response } = await apiClient.GET('/audit/events', {
    params: { query: { page_size: 100 } },
  });
  if (!data) throw new ApiError(errorMessage(error, '无法读取审计事件'), response.status);
  return data.items;
}
