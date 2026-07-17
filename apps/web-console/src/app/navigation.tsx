import {
  AppstoreOutlined,
  AuditOutlined,
  BookOutlined,
  BugOutlined,
  CloudServerOutlined,
  ControlOutlined,
  DatabaseOutlined,
  FileTextOutlined,
  RobotOutlined,
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

export const P7_NAVIGATION: NavigationEntry[] = [
  { key: '/', labelKey: 'dashboard', icon: <AppstoreOutlined /> },
  { key: '/access', labelKey: 'access', icon: <TeamOutlined />, oidcOnly: true },
  { key: '/tasks', labelKey: 'tasks', icon: <SafetyCertificateOutlined /> },
  { key: '/models', labelKey: 'models', icon: <CloudServerOutlined /> },
  { key: '/agents', labelKey: 'agents', icon: <RobotOutlined /> },
  { key: '/knowledge', labelKey: 'knowledge', icon: <BookOutlined /> },
  { key: '/assets', labelKey: 'assets', icon: <DatabaseOutlined /> },
  { key: '/validation', labelKey: 'validation', icon: <BugOutlined /> },
  { key: '/sandboxes', labelKey: 'sandboxes', icon: <ControlOutlined /> },
  { key: '/policies', labelKey: 'policies', icon: <SafetyCertificateOutlined /> },
  { key: '/audit', labelKey: 'audit', icon: <AuditOutlined /> },
  { key: '/reports', labelKey: 'reports', icon: <FileTextOutlined /> },
  { key: '/system', labelKey: 'system', icon: <SettingOutlined /> },
];

export const P7_ROUTE_KEYS = P7_NAVIGATION.map((entry) => entry.key);

export function getNavigationItems(messages: Messages, includeOidcItems: boolean) {
  return P7_NAVIGATION.filter((entry) => includeOidcItems || !entry.oidcOnly).map((entry) => ({
    key: entry.key,
    icon: entry.icon,
    label: <Link to={entry.key}>{messages[entry.labelKey]}</Link>,
  }));
}

export function selectNavigationKey(pathname: string) {
  return [...P7_ROUTE_KEYS]
    .sort((left, right) => right.length - left.length)
    .find((key) => pathname === key || (key !== '/' && pathname.startsWith(`${key}/`))) ?? '/';
}
