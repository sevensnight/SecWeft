import { Alert, Button, Result, Spin, Typography } from 'antd';
import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';

import { queryClient } from '../app/query-client';
import { useSessionStore } from '../stores/session';
import { AuthContext } from './AuthContext';
import { authMode, oidcConfigured } from './config';
import { applyOidcUser, completeSigninOnce, getUserManager, safeReturnUrl } from './oidc';

type AuthStatus = 'checking' | 'authenticated' | 'unauthenticated' | 'error';

export function AuthBoundary({ children }: { children: ReactNode }) {
  const clearOidcSession = useSessionStore((state) => state.clearOidcSession);
  const [status, setStatus] = useState<AuthStatus>(
    authMode === 'compatibility'
      ? 'authenticated'
      : oidcConfigured
        ? 'checking'
        : 'error',
  );
  const [error, setError] = useState<string | null>(
    authMode === 'oidc' && !oidcConfigured
      ? '部署配置缺少 OIDC authority。'
      : null,
  );

  useEffect(() => {
    if (authMode !== 'oidc' || !oidcConfigured) return undefined;
    const userManager = getUserManager();
    const unload = () => {
      clearOidcSession();
      queryClient.clear();
      setStatus('unauthenticated');
    };
    const removeLoaded = userManager.events.addUserLoaded((user) => {
      applyOidcUser(user);
      setStatus('authenticated');
    });
    const removeUnloaded = userManager.events.addUserUnloaded(unload);
    const removeExpired = userManager.events.addAccessTokenExpired(unload);
    let cancelled = false;
    const initialize = async () => {
      try {
        const isCallback =
          window.location.pathname === '/auth/callback'
          && new URLSearchParams(window.location.search).has('code');
        const user = isCallback ? await completeSigninOnce() : await userManager.getUser();
        if (cancelled) return;
        if (user && !user.expired) {
          applyOidcUser(user);
          setStatus('authenticated');
          if (isCallback) {
            window.history.replaceState({}, document.title, safeReturnUrl(user.state));
          }
        } else {
          clearOidcSession();
          setStatus('unauthenticated');
        }
      } catch {
        if (cancelled) return;
        clearOidcSession();
        await userManager.clearStaleState();
        setError('身份提供方响应无法验证，请重新登录。');
        setStatus('error');
      }
    };
    void initialize();
    return () => {
      cancelled = true;
      removeLoaded();
      removeUnloaded();
      removeExpired();
    };
  }, [clearOidcSession]);

  const login = useCallback(async () => {
    if (!oidcConfigured) return;
    setError(null);
    setStatus('checking');
    const returnUrl = `${window.location.pathname}${window.location.search}`;
    await getUserManager().signinRedirect({ state: { returnUrl } });
  }, []);

  const logout = useCallback(async () => {
    if (!oidcConfigured) return;
    queryClient.clear();
    clearOidcSession();
    await getUserManager().signoutRedirect();
  }, [clearOidcSession]);

  const actions = useMemo(() => ({ login, logout }), [login, logout]);

  if (status === 'checking') {
    return (
      <main className="auth-screen" aria-live="polite">
        <Spin size="large" />
        <Typography.Text>正在验证企业身份…</Typography.Text>
      </main>
    );
  }
  if (status === 'error') {
    return (
      <main className="auth-screen">
        <Result
          status="error"
          title="企业身份验证失败"
          subTitle={error}
          extra={oidcConfigured ? <Button type="primary" onClick={() => void login()}>重新登录</Button> : null}
        />
      </main>
    );
  }
  if (status === 'unauthenticated') {
    return (
      <main className="auth-screen">
        <Result
          icon={<div className="auth-mark">VL</div>}
          title="VulnLab 企业控制台"
          subTitle="使用组织的 OpenID Connect 身份登录；控制台不会持久化访问令牌。"
          extra={<Button type="primary" size="large" onClick={() => void login()}>使用企业身份登录</Button>}
        />
        <Alert
          type="info"
          showIcon
          message="Authorization Code + PKCE"
          description="访问令牌只保存在当前页面内存中；刷新或关闭页面后需要重新建立会话。"
        />
      </main>
    );
  }
  return <AuthContext.Provider value={actions}>{children}</AuthContext.Provider>;
}
