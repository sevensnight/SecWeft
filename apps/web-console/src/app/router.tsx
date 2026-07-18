import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
} from '@tanstack/react-router';

import { AppShell } from '../layouts/AppShell';

const rootRoute = createRootRoute({ component: AppShell });

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: lazyRouteComponent(
    () => import('../modules/dashboard/pages/HomePage'),
    'HomePage',
  ),
});

const accessRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/access',
  component: lazyRouteComponent(
    () => import('../modules/identity/pages/EnterpriseAccessPage'),
    'EnterpriseAccessPage',
  ),
});

const tasksRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/tasks',
  component: lazyRouteComponent(
    () => import('../modules/tasks/pages/TaskListPage'),
    'TaskListPage',
  ),
});

const taskDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/tasks/$taskId',
  component: lazyRouteComponent(
    () => import('../modules/tasks/pages/TaskDetailPage'),
    'TaskDetailPage',
  ),
});

const modelsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/models',
  component: lazyRouteComponent(
    () => import('../modules/models/pages/ModelsPage'),
    'ModelsPage',
  ),
});

const agentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/agents',
  component: lazyRouteComponent(
    () => import('../modules/agents/pages/AgentsPage'),
    'AgentsPage',
  ),
});

const knowledgeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/knowledge',
  component: lazyRouteComponent(
    () => import('../modules/knowledge/pages/KnowledgePage'),
    'KnowledgePage',
  ),
});

const assetsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/assets',
  component: lazyRouteComponent(
    () => import('../modules/assets/pages/AssetsPage'),
    'AssetsPage',
  ),
});

const validationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/validation',
  component: lazyRouteComponent(
    () => import('../modules/validation/pages/ValidationPage'),
    'ValidationPage',
  ),
});

const casesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/cases',
  component: lazyRouteComponent(
    () => import('../modules/cases/pages/CasesPage'),
    'CasesPage',
  ),
});

const caseDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/cases/$caseId',
  component: lazyRouteComponent(
    () => import('../modules/cases/pages/CaseDetailPage'),
    'CaseDetailPage',
  ),
});

const evaluationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/evaluations',
  component: lazyRouteComponent(
    () => import('../modules/evaluations/pages/EvaluationsPage'),
    'EvaluationsPage',
  ),
});

const evaluationRunDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/evaluations/$runId',
  component: lazyRouteComponent(
    () => import('../modules/evaluations/pages/EvaluationRunDetailPage'),
    'EvaluationRunDetailPage',
  ),
});

const releasesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/releases',
  component: lazyRouteComponent(
    () => import('../modules/releases/pages/ReleasesPage'),
    'ReleasesPage',
  ),
});

const releaseCandidateDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/releases/$candidateId',
  component: lazyRouteComponent(
    () => import('../modules/releases/pages/ReleaseCandidateDetailPage'),
    'ReleaseCandidateDetailPage',
  ),
});

const sandboxesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sandboxes',
  component: lazyRouteComponent(
    () => import('../modules/sandboxes/pages/SandboxesPage'),
    'SandboxesPage',
  ),
});

const policiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/policies',
  component: lazyRouteComponent(
    () => import('../modules/policies/pages/PoliciesPage'),
    'PoliciesPage',
  ),
});

const auditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/audit',
  component: lazyRouteComponent(
    () => import('../modules/audit/pages/AuditPage'),
    'AuditPage',
  ),
});

const reportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reports',
  component: lazyRouteComponent(
    () => import('../modules/reports/pages/ReportsPage'),
    'ReportsPage',
  ),
});

const systemRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/system',
  component: lazyRouteComponent(
    () => import('../modules/system/pages/SystemPage'),
    'SystemPage',
  ),
});

const routeTree = rootRoute.addChildren([
  dashboardRoute,
  accessRoute,
  tasksRoute,
  taskDetailRoute,
  modelsRoute,
  agentsRoute,
  knowledgeRoute,
  assetsRoute,
  validationRoute,
  casesRoute,
  caseDetailRoute,
  evaluationsRoute,
  evaluationRunDetailRoute,
  releasesRoute,
  releaseCandidateDetailRoute,
  sandboxesRoute,
  policiesRoute,
  auditRoute,
  reportsRoute,
  systemRoute,
]);

export const router = createRouter({
  routeTree,
  defaultPreload: 'intent',
  defaultPreloadStaleTime: 30_000,
});

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
