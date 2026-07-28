import { afterEach, describe, expect, it, vi } from 'vitest';

const API_KEY_SESSION_STORAGE_KEY = 'vulnlab.compatibility.apiKey';

describe('session store API key persistence', () => {
  afterEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    vi.resetModules();
  });

  it('keeps the compatibility API key only in tab session storage', async () => {
    vi.resetModules();
    const { useSessionStore } = await import('./session');

    useSessionStore.getState().setApiKey('test-admin-key');

    expect(useSessionStore.getState().apiKey).toBe('test-admin-key');
    expect(sessionStorage.getItem(API_KEY_SESSION_STORAGE_KEY)).toBe('test-admin-key');
    expect(localStorage.getItem(API_KEY_SESSION_STORAGE_KEY)).toBeNull();

    useSessionStore.getState().clearApiKey();

    expect(useSessionStore.getState().apiKey).toBeNull();
    expect(sessionStorage.getItem(API_KEY_SESSION_STORAGE_KEY)).toBeNull();
  });

  it('hydrates the compatibility API key after a refresh-equivalent module reload', async () => {
    sessionStorage.setItem(API_KEY_SESSION_STORAGE_KEY, 'refresh-safe-key');
    vi.resetModules();

    const { useSessionStore } = await import('./session');

    expect(useSessionStore.getState().apiKey).toBe('refresh-safe-key');
  });
});
