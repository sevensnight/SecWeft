import { describe, expect, it } from 'vitest';

import { safeReturnUrl } from './oidc';

describe('safeReturnUrl', () => {
  it('keeps only same-origin relative application paths', () => {
    expect(safeReturnUrl({ returnUrl: '/access?project=one' })).toBe(
      '/access?project=one',
    );
    expect(safeReturnUrl({ returnUrl: '//attacker.example/path' })).toBe('/');
    expect(safeReturnUrl({ returnUrl: 'https://attacker.example/path' })).toBe('/');
    expect(safeReturnUrl({ returnUrl: 42 })).toBe('/');
    expect(safeReturnUrl(null)).toBe('/');
  });
});
