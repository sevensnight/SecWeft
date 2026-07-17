import createClient, { type Middleware } from 'openapi-fetch';

import type { paths } from '@vulnlab/shared-types';

export interface ClientOptions {
  baseUrl?: string;
  getAccessToken?: () => string | null;
  getApiKey?: () => string | null;
  getProjectId?: () => string | null;
  getRequestId?: () => string;
}

export function createVulnLabClient(options: ClientOptions) {
  const client = createClient<paths>({ baseUrl: options.baseUrl ?? '/api/v1' });
  const auth: Middleware = {
    onRequest({ request }) {
      const accessToken = options.getAccessToken?.();
      const apiKey = options.getApiKey?.();
      const projectId = options.getProjectId?.();
      if (accessToken) request.headers.set('Authorization', `Bearer ${accessToken}`);
      else if (apiKey) request.headers.set('X-API-Key', apiKey);
      if (projectId) request.headers.set('X-Project-ID', projectId);
      request.headers.set('X-Request-ID', options.getRequestId?.() ?? crypto.randomUUID());
      return request;
    },
  };
  client.use(auth);
  return client;
}
