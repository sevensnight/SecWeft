import {
  InMemoryWebStorage,
  UserManager,
  WebStorageStateStore,
  type User,
} from 'oidc-client-ts';

import { useSessionStore } from '../stores/session';
import {
  oidcAcrValues,
  oidcAuthority,
  oidcClientId,
  oidcConfigured,
  oidcScope,
} from './config';

let manager: UserManager | null = null;
let callbackPromise: Promise<User> | null = null;

export function getUserManager(): UserManager {
  if (!oidcConfigured) throw new Error('OIDC is not configured for this deployment');
  if (manager) return manager;
  manager = new UserManager({
    authority: oidcAuthority,
    client_id: oidcClientId,
    redirect_uri: `${window.location.origin}/auth/callback`,
    post_logout_redirect_uri: window.location.origin,
    response_type: 'code',
    scope: oidcScope,
    ...(oidcAcrValues ? { acr_values: oidcAcrValues } : {}),
    automaticSilentRenew: false,
    monitorSession: false,
    loadUserInfo: false,
    stateStore: new WebStorageStateStore({
      prefix: 'vulnlab.oidc.state.',
      store: window.sessionStorage,
    }),
    userStore: new WebStorageStateStore({
      prefix: 'vulnlab.oidc.user.',
      store: new InMemoryWebStorage(),
    }),
  });
  return manager;
}

export function safeReturnUrl(state: unknown): string {
  if (typeof state !== 'object' || state === null || !('returnUrl' in state)) return '/';
  const returnUrl = (state as { returnUrl?: unknown }).returnUrl;
  return typeof returnUrl === 'string' && returnUrl.startsWith('/') && !returnUrl.startsWith('//')
    ? returnUrl
    : '/';
}

export function completeSigninOnce(): Promise<User> {
  callbackPromise ??= getUserManager().signinRedirectCallback();
  return callbackPromise;
}

export function applyOidcUser(user: User): void {
  if (!user.access_token || user.expired) throw new Error('OIDC access token is missing or expired');
  const displayName =
    (typeof user.profile.preferred_username === 'string' && user.profile.preferred_username)
    || (typeof user.profile.name === 'string' && user.profile.name)
    || user.profile.sub;
  const { setOidcSession } = useSessionStore.getState();
  setOidcSession({
    accessToken: user.access_token,
    displayName,
    expiresAt: user.expires_at ?? null,
  });
}
