import type { AppLocale } from '../stores/preferences';

const MESSAGES = {
  'zh-CN': { dashboard: '综合态势', tasks: '任务中心', system: '系统状态' },
  'en-US': { dashboard: 'Overview', tasks: 'Tasks', system: 'System' },
} as const;

export function getMessages(locale: AppLocale) {
  return MESSAGES[locale];
}
