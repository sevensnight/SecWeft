import { describe, expect, it } from 'vitest';

import { APP_ROUTE_KEYS, selectNavigationKey } from './navigation';

describe('console navigation', () => {
  it('keeps the console route surface wired', () => {
    expect(APP_ROUTE_KEYS).toEqual(expect.arrayContaining([
      '/',
      '/tasks',
      '/models',
      '/agents',
      '/knowledge',
      '/assets',
      '/validation',
      '/cases',
      '/evaluations',
      '/sandboxes',
      '/policies',
      '/audit',
      '/reports',
      '/system',
    ]));
  });

  it('selects the owning menu entry for nested routes', () => {
    expect(selectNavigationKey('/tasks/abc')).toBe('/tasks');
    expect(selectNavigationKey('/cases/abc')).toBe('/cases');
    expect(selectNavigationKey('/evaluations/run-1')).toBe('/evaluations');
    expect(selectNavigationKey('/validation')).toBe('/validation');
    expect(selectNavigationKey('/unknown')).toBe('/');
  });
});
