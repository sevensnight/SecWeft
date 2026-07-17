#!/usr/bin/env node
import { createHash, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const workspaceRequire = createRequire(
  new URL('../../apps/web-console/package.json', import.meta.url),
);
const playwrightModule = await import(
  pathToFileURL(workspaceRequire.resolve('@playwright/test')).href
);
const { chromium } = playwrightModule.default ?? playwrightModule;

const baseUrl = (process.env.P1_KEYCLOAK_URL ?? 'http://127.0.0.1:8081').replace(/\/$/, '');
const realm = process.env.P1_KEYCLOAK_REALM ?? 'vulnlab-development';
const adminUser = process.env.P1_KEYCLOAK_ADMIN_USER;
const adminPassword = process.env.P1_KEYCLOAK_ADMIN_PASSWORD;
if (!adminUser || !adminPassword) throw new Error('Keycloak admin environment is required');

const form = (value) => new URLSearchParams(value);
const jsonFetch = async (url, init) => {
  const response = await fetch(url, init);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`HTTP ${response.status} from ${new URL(url).pathname}`);
  return { response, body };
};
const base64url = (value) => Buffer.from(value).toString('base64url');
const decodePart = (value) => JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));

let userId;
let browser;
let callbackServer;
let profileChecks;
try {
  const admin = await jsonFetch(`${baseUrl}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: adminUser,
      password: adminPassword,
    }),
  });
  const adminToken = admin.body.access_token;
  if (typeof adminToken !== 'string') throw new Error('Admin token is missing');
  const realmConfiguration = await jsonFetch(
    `${baseUrl}/admin/realms/${realm}`,
    { headers: { Authorization: `Bearer ${adminToken}` } },
  );
  const profile = await jsonFetch(
    `${baseUrl}/admin/realms/${realm}/users/profile`,
    { headers: { Authorization: `Bearer ${adminToken}` } },
  );
  const tenantAttribute = profile.body.attributes?.find(
    (attribute) => attribute.name === 'tenant_id',
  );
  profileChecks = {
    short_lived_access_token: realmConfiguration.body.accessTokenLifespan <= 300,
    refresh_token_rotation:
      realmConfiguration.body.revokeRefreshToken === true &&
      realmConfiguration.body.refreshTokenMaxReuse === 0,
    login_brute_force_protection: realmConfiguration.body.bruteForceProtected === true,
    identity_events_enabled:
      realmConfiguration.body.eventsEnabled === true &&
      realmConfiguration.body.adminEventsEnabled === true,
    tenant_profile_managed: tenantAttribute?.multivalued === false,
    tenant_profile_admin_only_edit:
      tenantAttribute?.permissions?.edit?.length === 1 &&
      tenantAttribute.permissions.edit[0] === 'admin',
    unmanaged_attributes_disabled:
      profile.body.unmanagedAttributePolicy === undefined ||
      profile.body.unmanagedAttributePolicy === 'DISABLED',
  };
  const suffix = randomBytes(6).toString('hex');
  const tenantId = randomUUID();
  const username = `p1-oidc-${suffix}`;
  const password = `${base64url(randomBytes(24))}!Aa1`;
  const createUser = await fetch(`${baseUrl}/admin/realms/${realm}/users`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${adminToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      enabled: true,
      firstName: 'P1',
      lastName: 'Acceptance',
      email: `${username}@example.test`,
      emailVerified: true,
      attributes: { tenant_id: [tenantId] },
      credentials: [{ type: 'password', value: password, temporary: false }],
    }),
  });
  if (createUser.status !== 201) throw new Error(`Unable to create test user: ${createUser.status}`);
  userId = createUser.headers.get('Location')?.split('/').at(-1);
  if (!userId) throw new Error('Created user id is missing');

  const discovery = await jsonFetch(
    `${baseUrl}/realms/${realm}/.well-known/openid-configuration`,
  );
  const verifier = base64url(randomBytes(48));
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = base64url(randomBytes(24));
  const redirectUri = 'http://127.0.0.1:8080/auth/callback';
  const authorizationUrl = new URL(discovery.body.authorization_endpoint);
  authorizationUrl.search = form({
    client_id: 'vulnlab-web-console',
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  }).toString();

  callbackServer = createServer((request, response) => {
    if (request.url?.startsWith('/auth/callback')) {
      response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      response.end('OIDC callback received');
      return;
    }
    response.writeHead(404).end();
  });
  await new Promise((resolve, reject) => {
    callbackServer.once('error', reject);
    callbackServer.listen(8080, '127.0.0.1', resolve);
  });
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(authorizationUrl.toString());
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  try {
    await page.locator('#kc-login').click({ noWaitAfter: true });
    await page.waitForURL((url) => url.toString().startsWith(redirectUri), { timeout: 20_000 });
  } catch (error) {
    const feedback = await page.locator('#input-error, .kc-feedback-text, .alert-error')
      .allTextContents().catch(() => []);
    throw new Error(
      `OIDC login did not redirect (${page.url()}): ${feedback.join(' ').trim() || 'no feedback'}`,
      { cause: error },
    );
  }
  const callbackUrl = new URL(page.url());
  if (callbackUrl.searchParams.get('state') !== state) throw new Error('OIDC state mismatch');
  const code = callbackUrl.searchParams.get('code');
  if (!code) throw new Error('Authorization code is missing');

  const tokenResult = await jsonFetch(discovery.body.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      grant_type: 'authorization_code',
      client_id: 'vulnlab-web-console',
      redirect_uri: redirectUri,
      code,
      code_verifier: verifier,
    }),
  });
  const accessToken = tokenResult.body.access_token;
  if (typeof accessToken !== 'string') throw new Error('Access token is missing');
  const [encodedHeader, encodedPayload, encodedSignature] = accessToken.split('.');
  if (!encodedHeader || !encodedPayload || !encodedSignature) throw new Error('JWT is malformed');
  const header = decodePart(encodedHeader);
  const payload = decodePart(encodedPayload);
  const jwks = await jsonFetch(discovery.body.jwks_uri);
  const jwk = jwks.body.keys?.find((candidate) => candidate.kid === header.kid);
  if (!jwk) throw new Error('JWT signing key is missing from JWKS');
  const signatureValid = verify(
    'RSA-SHA256',
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(encodedSignature, 'base64url'),
  );
  const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const checks = {
    ...profileChecks,
    authorization_code_pkce: tokenResult.body.token_type === 'Bearer',
    issuer_exact: payload.iss === `${baseUrl}/realms/${realm}`,
    audience_mapped: audience.includes('vulnlab-control-plane'),
    tenant_claim_mapped: payload.tenant_id === tenantId,
    subject_stable: payload.sub === userId,
    signature_verified_from_jwks: signatureValid,
    implicit_flow_absent: !callbackUrl.hash,
  };
  console.log(JSON.stringify({
    valid: Object.values(checks).every(Boolean),
    checks,
    ...(!checks.tenant_claim_mapped || !checks.subject_stable
      ? {
          diagnostics: {
            expected_tenant: tenantId,
            actual_tenant: payload.tenant_id,
            expected_subject: userId,
            actual_subject: payload.sub,
            preferred_username: payload.preferred_username,
          },
        }
      : {}),
  }, null, 2));
  if (!Object.values(checks).every(Boolean)) process.exitCode = 1;
} finally {
  if (browser) await browser.close();
  if (callbackServer?.listening) {
    await new Promise((resolve, reject) => {
      callbackServer.close((error) => (error ? reject(error) : resolve()));
    });
  }
  if (userId) {
    const admin = await jsonFetch(`${baseUrl}/realms/master/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form({
        grant_type: 'password',
        client_id: 'admin-cli',
        username: adminUser,
        password: adminPassword,
      }),
    });
    await fetch(`${baseUrl}/admin/realms/${realm}/users/${userId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${admin.body.access_token}` },
    });
  }
}
