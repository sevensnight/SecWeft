import { describe, expect, it } from 'vitest';

import { countTaskStatuses } from './task-status';

describe('countTaskStatuses', () => {
  it('groups task projections without mutating input', () => {
    const tasks = (
      [{ status: 'running' }, { status: 'running' }, { status: 'succeeded' }]
    ) as Parameters<typeof countTaskStatuses>[0];
    expect(countTaskStatuses(tasks)).toEqual({ running: 2, succeeded: 1 });
  });
});
