import { afterEach, describe, expect, it, vi } from 'vitest';

import { createVulnLabClient } from '../src/client';

const SESSION = {
  user_id: '00000000-0000-4000-8000-000000000001',
  tenant_id: '00000000-0000-4000-8000-000000000002',
  username: 'p1-user',
  email: null,
  tenant_status: 'ACTIVE',
  roles: ['readonly_user'],
  permissions: ['project.read'],
  projects: [],
};

afterEach(() => vi.unstubAllGlobals());

describe('createVulnLabClient authentication middleware', () => {
  it('prefers an in-memory bearer token and propagates project/request context', async () => {
    const captured: Request[] = [];
    vi.stubGlobal('fetch', vi.fn(async (request: Request) => {
      captured.push(request);
      return new Response(JSON.stringify(SESSION), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }));
    const client = createVulnLabClient({
      baseUrl: 'https://api.example.test/api/v1',
      getAccessToken: () => 'memory-only-access-token',
      getApiKey: () => 'compatibility-key-must-not-be-used',
      getProjectId: () => '00000000-0000-4000-8000-000000000003',
      getRequestId: () => '00000000-0000-4000-8000-000000000004',
    });

    const result = await client.GET('/session');
    const request = captured[0];
    if (!request) throw new Error('fetch was not called');

    expect(result.data?.username).toBe('p1-user');
    expect(request.headers.get('Authorization')).toBe('Bearer memory-only-access-token');
    expect(request.headers.has('X-API-Key')).toBe(false);
    expect(request.headers.get('X-Project-ID')).toBe(
      '00000000-0000-4000-8000-000000000003',
    );
    expect(request.headers.get('X-Request-ID')).toBe(
      '00000000-0000-4000-8000-000000000004',
    );
  });

  it('uses API-key authentication only when no bearer token exists', async () => {
    const captured: Request[] = [];
    vi.stubGlobal('fetch', vi.fn(async (request: Request) => {
      captured.push(request);
      return new Response(JSON.stringify(SESSION), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }));
    const client = createVulnLabClient({
      baseUrl: 'https://api.example.test/api/v1',
      getAccessToken: () => null,
      getApiKey: () => 'compatibility-key',
      getRequestId: () => '00000000-0000-4000-8000-000000000004',
    });

    await client.GET('/session');
    const request = captured[0];
    if (!request) throw new Error('fetch was not called');

    expect(request.headers.get('X-API-Key')).toBe('compatibility-key');
    expect(request.headers.has('Authorization')).toBe(false);
  });
});
