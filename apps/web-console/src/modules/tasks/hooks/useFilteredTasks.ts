import type { Task } from '@vulnlab/shared-types';
import { useEffect, useMemo, useRef, useState } from 'react';

import type { TaskFilterRequest, TaskFilterResponse } from '../types';

export function useFilteredTasks(tasks: Task[], query: string): Task[] {
  const [filtered, setFiltered] = useState(tasks);
  const requestId = useRef(0);
  const fallback = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    return normalized
      ? tasks.filter((task) => task.title.toLocaleLowerCase().includes(normalized))
      : tasks;
  }, [query, tasks]);

  useEffect(() => {
    if (typeof Worker === 'undefined') return;
    const worker = new Worker(new URL('../../../workers/task-filter.worker.ts', import.meta.url), { type: 'module' });
    const nextRequestId = ++requestId.current;
    worker.onmessage = (event: MessageEvent<TaskFilterResponse>) => {
      if (event.data.requestId === nextRequestId) setFiltered(event.data.tasks);
    };
    const request: TaskFilterRequest = { requestId: nextRequestId, query, tasks };
    worker.postMessage(request);
    return () => worker.terminate();
  }, [query, tasks]);

  return typeof Worker === 'undefined' ? fallback : filtered;
}
