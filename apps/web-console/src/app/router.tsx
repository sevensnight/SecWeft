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
    () => import('../modules/dashboard/pages/DashboardPage'),
    'DashboardPage',
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
const systemRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/system',
  component: lazyRouteComponent(
    () => import('../modules/system/pages/SystemPage'),
    'SystemPage',
  ),
});
const routeTree = rootRoute.addChildren([dashboardRoute, tasksRoute, taskDetailRoute, systemRoute]);

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
