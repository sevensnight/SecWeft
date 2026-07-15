import type { Task } from '@vulnlab/shared-types';

export interface TaskFilterRequest {
  requestId: number;
  query: string;
  tasks: Task[];
}

export interface TaskFilterResponse {
  requestId: number;
  tasks: Task[];
}
