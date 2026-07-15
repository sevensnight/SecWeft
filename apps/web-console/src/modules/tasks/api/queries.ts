import { queryOptions } from '@tanstack/react-query';

import { getTask, listTaskEvents, listTasks } from '../../../services/api';

export const taskKeys = {
  all: ['tasks'] as const,
  detail: (taskId: string) => ['tasks', taskId] as const,
  events: (taskId: string) => ['tasks', taskId, 'events'] as const,
};

export const tasksQuery = () => queryOptions({ queryKey: taskKeys.all, queryFn: () => listTasks() });
export const taskQuery = (taskId: string) => queryOptions({
  queryKey: taskKeys.detail(taskId),
  queryFn: () => getTask(taskId),
});
export const taskEventsQuery = (taskId: string) => queryOptions({
  queryKey: taskKeys.events(taskId),
  queryFn: () => listTaskEvents(taskId),
});
