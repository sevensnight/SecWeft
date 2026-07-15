import { createVulnLabClient } from '@vulnlab/api-client';
import type { SystemRequirements, Task, TaskEvent } from '@vulnlab/shared-types';

import { useSessionStore } from '../stores/session';

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(`${status}: ${message}`);
    this.name = 'ApiError';
  }
}

export const apiClient = createVulnLabClient({
  getApiKey: () => useSessionStore.getState().apiKey,
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
