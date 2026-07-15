import createClient, { type Middleware } from 'openapi-fetch';

import type { paths } from '@vulnlab/shared-types';

export interface ClientOptions {
  baseUrl?: string;
  getApiKey: () => string | null;
  getRequestId?: () => string;
}

export function createVulnLabClient(options: ClientOptions) {
  const client = createClient<paths>({ baseUrl: options.baseUrl ?? '/api/v1' });
  const auth: Middleware = {
    onRequest({ request }) {
      const apiKey = options.getApiKey();
      if (apiKey) request.headers.set('X-API-Key', apiKey);
      request.headers.set('X-Request-ID', options.getRequestId?.() ?? crypto.randomUUID());
      return request;
    },
  };
  client.use(auth);
  return client;
}
