import { describe, expect, it } from 'vitest';

import { P7_ROUTE_KEYS, selectNavigationKey } from './navigation';

describe('P7 navigation', () => {
  it('keeps the enterprise console route surface wired', () => {
    expect(P7_ROUTE_KEYS).toEqual(expect.arrayContaining([
      '/',
      '/tasks',
      '/models',
      '/agents',
      '/knowledge',
      '/assets',
      '/validation',
      '/sandboxes',
      '/policies',
      '/audit',
      '/reports',
      '/system',
    ]));
  });

  it('selects the owning menu entry for nested routes', () => {
    expect(selectNavigationKey('/tasks/abc')).toBe('/tasks');
    expect(selectNavigationKey('/validation')).toBe('/validation');
    expect(selectNavigationKey('/unknown')).toBe('/');
  });
});
