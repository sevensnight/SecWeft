import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { App as AntApp, ConfigProvider, theme } from 'antd';
import enUS from 'antd/locale/en_US';
import zhCN from 'antd/locale/zh_CN';
import { useEffect } from 'react';

import { ErrorBoundary } from '../components/ErrorBoundary';
import { AuthBoundary } from '../auth/AuthBoundary';
import { usePreferencesStore } from '../stores/preferences';
import { LocalizedTextRuntime } from '../i18n/LocalizedTextRuntime';
import { queryClient } from './query-client';
import { router } from './router';

export function AppProviders() {
  const colorMode = usePreferencesStore((state) => state.colorMode);
  const locale = usePreferencesStore((state) => state.locale);

  useEffect(() => {
    document.documentElement.dataset.colorMode = colorMode;
  }, [colorMode]);

  return (
    <ErrorBoundary>
      <ConfigProvider
        button={{ autoInsertSpace: false }}
        locale={locale === 'zh-CN' ? zhCN : enUS}
        theme={{
          algorithm: colorMode === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm,
          token: { borderRadius: 8, colorPrimary: '#1677ff' },
        }}
      >
        <AntApp>
          <LocalizedTextRuntime />
          <QueryClientProvider client={queryClient}>
            <AuthBoundary>
              <RouterProvider router={router} />
            </AuthBoundary>
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>
    </ErrorBoundary>
  );
}
