export type AuthMode = 'compatibility' | 'oidc';

const requestedMode = import.meta.env.VITE_AUTH_MODE?.trim().toLowerCase();

export const authMode: AuthMode = requestedMode === 'oidc' ? 'oidc' : 'compatibility';
export const oidcAuthority = import.meta.env.VITE_OIDC_AUTHORITY?.trim().replace(/\/$/, '') ?? '';
export const oidcClientId = import.meta.env.VITE_OIDC_CLIENT_ID?.trim() || 'vulnlab-web-console';
export const oidcScope = import.meta.env.VITE_OIDC_SCOPE?.trim() || 'openid profile email';
export const oidcAcrValues = import.meta.env.VITE_OIDC_ACR_VALUES?.trim() || undefined;

export const oidcConfigured = authMode === 'oidc' && oidcAuthority.length > 0;
