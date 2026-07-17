#!/usr/bin/env node
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const workspaceRequire = createRequire(
  new URL('../../apps/web-console/package.json', import.meta.url),
);
const playwrightModule = await import(
  pathToFileURL(workspaceRequire.resolve('@playwright/test')).href
);
const { chromium } = playwrightModule.default ?? playwrightModule;

const gateway = new URL(process.env.P1_GATEWAY_URL ?? 'http://127.0.0.1:8080');
const oidcOrigin = new URL(
  process.env.P1_OIDC_BROWSER_ORIGIN ?? 'http://127.0.0.1:8081',
).origin;
const timeout = Number(process.env.P1_BROWSER_TIMEOUT_MS ?? '20000');
const expectedAcrValues = process.env.P1_EXPECTED_ACR_VALUES?.trim() || undefined;
if (!Number.isFinite(timeout) || timeout < 1000 || timeout > 120000) {
  throw new Error('P1_BROWSER_TIMEOUT_MS must be between 1000 and 120000');
}

let browser;
try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const cspErrors = [];
  let discoveryStatus;
  page.on('console', (message) => {
    const value = message.text();
    if (/content security policy|refused to connect/i.test(value)) cspErrors.push(value);
  });
  page.on('response', (response) => {
    if (response.url().includes('/.well-known/openid-configuration')) {
      discoveryStatus = response.status();
    }
  });

  const response = await page.goto(gateway.href, {
    waitUntil: 'domcontentloaded',
    timeout,
  });
  if (!response) throw new Error('Gateway navigation returned no response');
  const csp = (await response.allHeaders())['content-security-policy'] ?? '';
  await page
    .getByRole('button', { name: '使用企业身份登录' })
    .click({ timeout });
  await page.waitForURL(
    (url) =>
      url.origin === oidcOrigin
      && url.pathname.includes('/protocol/openid-connect/auth'),
    { timeout, waitUntil: 'domcontentloaded' },
  );

  const authorizationUrl = new URL(page.url());
  const codeChallenge = authorizationUrl.searchParams.get('code_challenge') ?? '';
  const checks = {
    gateway_status_ok: response.ok(),
    csp_allows_configured_oidc_origin: csp.includes(
      `connect-src 'self' ${oidcOrigin}`,
    ),
    oidc_discovery_succeeded: discoveryStatus === 200,
    authorization_code_only:
      authorizationUrl.searchParams.get('response_type') === 'code',
    pkce_s256:
      authorizationUrl.searchParams.get('code_challenge_method') === 'S256'
      && codeChallenge.length >= 43,
    callback_is_same_gateway_origin:
      authorizationUrl.searchParams.get('redirect_uri')
      === `${gateway.origin}/auth/callback`,
    configured_acr_values_requested:
      expectedAcrValues === undefined
      || authorizationUrl.searchParams.get('acr_values') === expectedAcrValues,
    no_token_in_browser_url:
      !authorizationUrl.searchParams.has('access_token')
      && !authorizationUrl.searchParams.has('id_token'),
    no_csp_connection_error: cspErrors.length === 0,
  };
  const failed = Object.entries(checks)
    .filter(([, valid]) => !valid)
    .map(([name]) => name);
  const result = {
    valid: failed.length === 0,
    gateway_origin: gateway.origin,
    oidc_origin: oidcOrigin,
    checks,
    failed,
  };
  console.log(JSON.stringify(result, null, 2));
  if (failed.length > 0) process.exitCode = 1;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  await browser?.close();
}
