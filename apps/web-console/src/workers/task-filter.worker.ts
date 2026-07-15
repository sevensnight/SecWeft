/// <reference lib="webworker" />

import type { TaskFilterRequest, TaskFilterResponse } from '../modules/tasks/types';

self.addEventListener('message', (event: MessageEvent<TaskFilterRequest>) => {
  const { query, requestId, tasks } = event.data;
  const normalized = query.trim().toLocaleLowerCase();
  const filtered = normalized.length === 0
    ? tasks
    : tasks.filter((task) => [task.title, task.target, task.status, task.approval_status]
        .some((value) => value.toLocaleLowerCase().includes(normalized)));
  const response: TaskFilterResponse = { requestId, tasks: filtered };
  self.postMessage(response);
});

export {};
