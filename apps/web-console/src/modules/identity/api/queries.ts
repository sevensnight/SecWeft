import { queryOptions } from '@tanstack/react-query';

import {
  getCurrentTenant,
  getEnterpriseSession,
  listAuditEvents,
  listEnterpriseRoles,
  listEnterpriseUsers,
  listProjects,
} from '../../../services/api';

export const enterpriseKeys = {
  session: ['enterprise', 'session'] as const,
  tenant: ['enterprise', 'tenant'] as const,
  projects: ['enterprise', 'projects'] as const,
  users: ['enterprise', 'users'] as const,
  roles: ['enterprise', 'roles'] as const,
  audit: ['enterprise', 'audit'] as const,
};

export const enterpriseSessionQuery = () => queryOptions({
  queryKey: enterpriseKeys.session,
  queryFn: getEnterpriseSession,
  staleTime: 15_000,
});

export const tenantQuery = () => queryOptions({
  queryKey: enterpriseKeys.tenant,
  queryFn: getCurrentTenant,
  staleTime: 30_000,
});

export const projectsQuery = () => queryOptions({
  queryKey: enterpriseKeys.projects,
  queryFn: listProjects,
  staleTime: 15_000,
});

export const enterpriseUsersQuery = () => queryOptions({
  queryKey: enterpriseKeys.users,
  queryFn: listEnterpriseUsers,
  staleTime: 15_000,
});

export const enterpriseRolesQuery = () => queryOptions({
  queryKey: enterpriseKeys.roles,
  queryFn: listEnterpriseRoles,
  staleTime: 30_000,
});

export const enterpriseAuditQuery = () => queryOptions({
  queryKey: enterpriseKeys.audit,
  queryFn: () => listAuditEvents(),
  staleTime: 10_000,
});
