import {
  AppstoreOutlined,
  AuditOutlined,
  BookOutlined,
  BugOutlined,
  CloudServerOutlined,
  ControlOutlined,
  DatabaseOutlined,
  FileTextOutlined,
  ExperimentOutlined,
  RobotOutlined,
  RocketOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined,
} from '@ant-design/icons';
import { Link } from '@tanstack/react-router';
import type { ReactNode } from 'react';

import type { getMessages } from '../i18n/messages';

type Messages = ReturnType<typeof getMessages>;

export interface NavigationEntry {
  key: string;
  labelKey: keyof Messages;
  icon: ReactNode;
  oidcOnly?: boolean;
}

export const APP_NAVIGATION: NavigationEntry[] = [
  { key: '/', labelKey: 'dashboard', icon: <AppstoreOutlined /> },
  { key: '/access', labelKey: 'access', icon: <TeamOutlined />, oidcOnly: true },
  { key: '/tasks', labelKey: 'tasks', icon: <SafetyCertificateOutlined /> },
  { key: '/models', labelKey: 'models', icon: <CloudServerOutlined /> },
  { key: '/agents', labelKey: 'agents', icon: <RobotOutlined /> },
  { key: '/knowledge', labelKey: 'knowledge', icon: <BookOutlined /> },
  { key: '/assets', labelKey: 'assets', icon: <DatabaseOutlined /> },
  { key: '/validation', labelKey: 'validation', icon: <BugOutlined /> },
  { key: '/cases', labelKey: 'cases', icon: <FileTextOutlined /> },
  { key: '/evaluations', labelKey: 'evaluations', icon: <ExperimentOutlined /> },
  { key: '/releases', labelKey: 'releases', icon: <RocketOutlined /> },
  { key: '/sandboxes', labelKey: 'sandboxes', icon: <ControlOutlined /> },
  { key: '/policies', labelKey: 'policies', icon: <SafetyCertificateOutlined /> },
  { key: '/audit', labelKey: 'audit', icon: <AuditOutlined />, oidcOnly: true },
  { key: '/reports', labelKey: 'reports', icon: <FileTextOutlined /> },
  { key: '/system', labelKey: 'system', icon: <SettingOutlined /> },
];

export const APP_ROUTE_KEYS = APP_NAVIGATION.map((entry) => entry.key);

export function getNavigationItems(messages: Messages, includeOidcItems: boolean) {
  return APP_NAVIGATION.filter((entry) => includeOidcItems || !entry.oidcOnly).map((entry) => ({
    key: entry.key,
    icon: entry.icon,
    label: <Link to={entry.key}>{messages[entry.labelKey]}</Link>,
  }));
}

export function selectNavigationKey(pathname: string) {
  return [...APP_ROUTE_KEYS]
    .sort((left, right) => right.length - left.length)
    .find((key) => pathname === key || (key !== '/' && pathname.startsWith(`${key}/`))) ?? '/';
}
