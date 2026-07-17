import {
  AppstoreOutlined,
  BulbOutlined,
  KeyOutlined,
  LogoutOutlined,
  MoonOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { Link, Outlet, useRouterState } from '@tanstack/react-router';
import { Badge, Button, Flex, Layout, Menu, Select, Space, Switch, Typography } from 'antd';
import { useMemo, useState } from 'react';

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

  const selectedKey = pathname.startsWith('/tasks') ? '/tasks' : pathname;
  const menuItems = useMemo(
    () => authMode === 'oidc'
      ? [
          { key: '/', icon: <AppstoreOutlined />, label: <Link to="/">{messages.dashboard}</Link> },
          { key: '/access', icon: <TeamOutlined />, label: <Link to="/access">身份与权限</Link> },
        ]
      : [
          { key: '/', icon: <AppstoreOutlined />, label: <Link to="/">{messages.dashboard}</Link> },
          { key: '/tasks', icon: <SafetyCertificateOutlined />, label: <Link to="/tasks">{messages.tasks}</Link> },
          { key: '/system', icon: <SettingOutlined />, label: <Link to="/system">{messages.system}</Link> },
        ],
    [messages],
  );

  const refreshQueries = async () => queryClient.invalidateQueries();

  return (
    <Layout className="app-layout">
      <Sider breakpoint="lg" collapsedWidth="0" className="app-sider">
        <div className="brand"><SafetyCertificateOutlined /><span>VulnLab</span></div>
        <Menu theme="dark" mode="inline" selectedKeys={[selectedKey]} items={menuItems} />
      </Sider>
      <Layout>
        <Header className="app-header">
          <Flex align="center" justify="space-between" gap="middle">
            <Space>
              <Typography.Text strong>模块二控制台</Typography.Text>
              <Badge status="processing" text={authMode === 'oidc' ? 'P1 企业身份与租户' : 'P0 兼容迁移'} />
            </Space>
            <Space wrap>
              <Select
                aria-label="语言"
                value={locale}
                onChange={setLocale}
                options={[{ value: 'zh-CN', label: '中文' }, { value: 'en-US', label: 'English' }]}
              />
              <Switch
                aria-label="深色模式"
                checked={colorMode === 'dark'}
                checkedChildren={<MoonOutlined />}
                unCheckedChildren={<BulbOutlined />}
                onChange={(checked) => setColorMode(checked ? 'dark' : 'light')}
              />
              {authMode === 'oidc' ? (
                <Button icon={<LogoutOutlined />} onClick={() => void auth.logout()}>
                  <UserOutlined /> {displayName ?? '企业用户'} · 退出
                </Button>
              ) : (
                <Button
                  icon={<KeyOutlined />}
                  type={apiKey ? 'default' : 'primary'}
                  onClick={() => setApiKeyOpen(true)}
                >
                  {apiKey ? '认证已配置' : '配置 API Key'}
                </Button>
              )}
            </Space>
          </Flex>
        </Header>
        <Content className="app-content">
          <AsyncBoundary><Outlet /></AsyncBoundary>
        </Content>
      </Layout>
      {authMode === 'compatibility' ? <ApiKeyDialog
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
      /> : null}
    </Layout>
  );
}
