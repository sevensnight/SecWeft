import {
  BulbOutlined,
  KeyOutlined,
  LogoutOutlined,
  MoonOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { Outlet, useRouterState } from '@tanstack/react-router';
import { Badge, Button, Flex, Layout, Menu, Select, Space, Switch, Typography } from 'antd';
import { useMemo, useState } from 'react';

import { getNavigationItems, selectNavigationKey } from '../app/navigation';
import { queryClient } from '../app/query-client';
import { useAuthActions } from '../auth/AuthContext';
import { authMode } from '../auth/config';
import { ApiKeyDialog } from '../components/ApiKeyDialog';
import { AsyncBoundary } from '../components/AsyncBoundary';
import { getMessages } from '../i18n/messages';
import { usePreferencesStore } from '../stores/preferences';
import { useSessionStore } from '../stores/session';

const { Header, Content, Sider } = Layout;

export function AppShell() {
  const [apiKeyOpen, setApiKeyOpen] = useState(false);
  const auth = useAuthActions();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const apiKey = useSessionStore((state) => state.apiKey);
  const displayName = useSessionStore((state) => state.displayName);
  const setApiKey = useSessionStore((state) => state.setApiKey);
  const clearApiKey = useSessionStore((state) => state.clearApiKey);
  const colorMode = usePreferencesStore((state) => state.colorMode);
  const locale = usePreferencesStore((state) => state.locale);
  const setColorMode = usePreferencesStore((state) => state.setColorMode);
  const setLocale = usePreferencesStore((state) => state.setLocale);
  const messages = getMessages(locale);
  const isZh = locale === 'zh-CN';
  const selectedKey = selectNavigationKey(pathname);
  const menuItems = useMemo(
    () => getNavigationItems(messages, authMode === 'oidc'),
    [messages],
  );

  const refreshQueries = async () => queryClient.invalidateQueries();

  return (
    <Layout className="app-layout">
      <Sider breakpoint="lg" collapsedWidth="0" className="app-sider">
        <div className="brand">
          <SafetyCertificateOutlined />
          <span>VulnLab</span>
        </div>
        <Menu theme="dark" mode="inline" selectedKeys={[selectedKey]} items={menuItems} />
      </Sider>
      <Layout>
        <Header className="app-header">
          <Flex align="center" justify="space-between" gap="middle">
            <Space>
              <Typography.Text strong>
                {isZh ? 'SecWeft 控制台' : 'SecWeft Console'}
              </Typography.Text>
              <Badge
                status="processing"
                text={
                  authMode === 'oidc'
                    ? (isZh ? '组织身份认证 / OIDC' : 'Organization identity / OIDC')
                    : (isZh ? 'API Key 认证' : 'API Key authentication')
                }
              />
            </Space>
            <Space wrap>
              <Select
                aria-label={isZh ? '语言' : 'Language'}
                value={locale}
                onChange={setLocale}
                options={[
                  { value: 'zh-CN', label: '简体中文' },
                  { value: 'en-US', label: 'English' },
                ]}
              />
              <Switch
                aria-label={isZh ? '深色模式' : 'Dark mode'}
                checked={colorMode === 'dark'}
                checkedChildren={<MoonOutlined />}
                unCheckedChildren={<BulbOutlined />}
                onChange={(checked) => setColorMode(checked ? 'dark' : 'light')}
              />
              {authMode === 'oidc' ? (
                <Button icon={<LogoutOutlined />} onClick={() => void auth.logout()}>
                  <UserOutlined /> {displayName ?? (isZh ? '组织用户' : 'Organization user')} ·{' '}
                  {isZh ? '退出' : 'Sign out'}
                </Button>
              ) : (
                <Button
                  icon={<KeyOutlined />}
                  type={apiKey ? 'default' : 'primary'}
                  onClick={() => setApiKeyOpen(true)}
                >
                  {apiKey
                    ? (isZh ? '认证已配置' : 'Authentication configured')
                    : (isZh ? '配置 API Key' : 'Configure API Key')}
                </Button>
              )}
            </Space>
          </Flex>
        </Header>
        <Content className="app-content">
          <AsyncBoundary>
            <Outlet />
          </AsyncBoundary>
        </Content>
      </Layout>
      {authMode === 'compatibility' ? (
        <ApiKeyDialog
          open={apiKeyOpen}
          onCancel={() => setApiKeyOpen(false)}
          onClear={() => {
            clearApiKey();
            void refreshQueries();
            setApiKeyOpen(false);
          }}
          onSubmit={(value) => {
            setApiKey(value);
            void refreshQueries();
            setApiKeyOpen(false);
          }}
        />
      ) : null}
    </Layout>
  );
}
