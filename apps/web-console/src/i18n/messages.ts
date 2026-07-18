import type { AppLocale } from '../stores/preferences';

const MESSAGES = {
  'zh-CN': {
    access: '身份与权限',
    agents: 'Agent / Skill',
    assets: '授权资产',
    audit: '审计中心',
    cases: '漏洞案件',
    dashboard: '综合态势',
    evaluations: 'AI 评测',
    releases: '发布治理',
    knowledge: '知识库',
    models: '模型管理',
    policies: '策略审批',
    reports: '报表中心',
    sandboxes: '沙箱中心',
    system: '系统状态',
    tasks: '任务中心',
    validation: '验证中心',
  },
  'en-US': {
    access: 'Access',
    agents: 'Agents / Skills',
    assets: 'Assets',
    audit: 'Audit',
    cases: 'Cases',
    dashboard: 'Overview',
    evaluations: 'Evaluations',
    releases: 'Releases',
    knowledge: 'Knowledge',
    models: 'Models',
    policies: 'Policies',
    reports: 'Reports',
    sandboxes: 'Sandboxes',
    system: 'System',
    tasks: 'Tasks',
    validation: 'Validation',
  },
} as const;

export function getMessages(locale: AppLocale) {
  return MESSAGES[locale];
}
