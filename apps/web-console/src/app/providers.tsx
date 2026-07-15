import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { App as AntApp, ConfigProvider, theme } from 'antd';
import enUS from 'antd/locale/en_US';
import zhCN from 'antd/locale/zh_CN';

import { ErrorBoundary } from '../components/ErrorBoundary';
import { usePreferencesStore } from '../stores/preferences';
import { queryClient } from './query-client';
import { router } from './router';

export function AppProviders() {
  const colorMode = usePreferencesStore((state) => state.colorMode);
  const locale = usePreferencesStore((state) => state.locale);
  return (
    <ErrorBoundary>
      <ConfigProvider
        locale={locale === 'zh-CN' ? zhCN : enUS}
        theme={{
          algorithm: colorMode === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm,
          token: { borderRadius: 8, colorPrimary: '#1677ff' },
        }}
      >
        <AntApp>
          <QueryClientProvider client={queryClient}>
            <RouterProvider router={router} />
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>
    </ErrorBoundary>
  );
}
