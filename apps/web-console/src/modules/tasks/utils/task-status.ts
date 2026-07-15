import type { Task } from '@vulnlab/shared-types';

export function countTaskStatuses(tasks: Task[]): Record<string, number> {
  return tasks.reduce<Record<string, number>>((counts, task) => {
    counts[task.status] = (counts[task.status] ?? 0) + 1;
    return counts;
  }, {});
}
