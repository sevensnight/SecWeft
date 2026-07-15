import { describe, expect, it } from 'vitest';

import { createVulnLabClient } from '../src/client';

describe('createVulnLabClient', () => {
  it('creates a typed client without persisting credentials', () => {
    const client = createVulnLabClient({ getApiKey: () => 'memory-only' });
    expect(client).toBeDefined();
    expect(JSON.stringify(client)).not.toContain('memory-only');
  });
});
