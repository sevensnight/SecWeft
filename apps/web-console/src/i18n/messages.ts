import type { AppLocale } from '../stores/preferences';

const ZH_CN_MESSAGES = {
  access: '身份与权限',
  agents: '智能体与技能',
  assets: '授权资产',
  audit: '审计中心',
  cases: '漏洞案件',
  dashboard: '综合态势',
  evaluations: 'AI 评测',
  releases: '发布治理',
  knowledge: '知识库',
  models: '模型管理',
  policies: '策略审批',
  reports: '报告中心',
  sandboxes: '沙箱中心',
  system: '系统状态',
  tasks: '任务中心',
  validation: '验证中心',
} as const;

const MESSAGES = {
  'zh-CN': ZH_CN_MESSAGES,
  'en-US': {
    access: 'Identity and Access',
    agents: 'Agents and Skills',
    assets: 'Authorized Assets',
    audit: 'Audit Center',
    cases: 'Vulnerability Cases',
    dashboard: 'Overview',
    evaluations: 'Evaluations',
    releases: 'Release Governance',
    knowledge: 'Knowledge Base',
    models: 'Model Management',
    policies: 'Policy and Approval',
    reports: 'Report Center',
    sandboxes: 'Sandbox Center',
    system: 'System Status',
    tasks: 'Task Center',
    validation: 'Validation Center',
  },
} as const;

export function getMessages(locale: AppLocale) {
  return MESSAGES[locale];
}
