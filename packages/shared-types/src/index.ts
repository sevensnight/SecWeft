import type { components, operations, paths } from './api.generated';

export type { components, operations, paths };

export type Task = components['schemas']['Task'];
export type TaskEvent = components['schemas']['TaskEvent'];
export type SystemRequirements = components['schemas']['SystemRequirements'];
export type EnterpriseSession = components['schemas']['Session'];
export type Tenant = components['schemas']['Tenant'];
export type Organization = components['schemas']['Organization'];
export type Project = components['schemas']['Project'];
export type EnterpriseUser = components['schemas']['User'];
export type EnterpriseRole = components['schemas']['Role'];
export type RoleAssignment = components['schemas']['RoleAssignment'];
export type AuditEvent = components['schemas']['AuditEvent'];
