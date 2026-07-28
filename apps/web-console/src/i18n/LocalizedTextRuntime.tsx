import { useEffect } from 'react';

import type { AppLocale } from '../stores/preferences';
import { usePreferencesStore } from '../stores/preferences';

const CJK_RE = /[\u3400-\u9fff]/;

const EXACT_ZH_TO_EN: Record<string, string> = {
  'SecWeft 控制台': 'SecWeft Console',
  '简体中文': 'Simplified Chinese',
  '语言': 'Language',
  '深色模式': 'Dark mode',
  '组织用户': 'Organization user',
  '组织身份认证 / OIDC': 'Organization identity / OIDC',
  'API Key 认证': 'API Key authentication',
  '退出': 'Sign out',
  '认证已配置': 'Authentication configured',
  '配置 API Key': 'Configure API Key',

  '正在验证组织身份…': 'Verifying organization identity…',
  '身份验证失败': 'Identity verification failed',
  '重新登录': 'Sign in again',
  '使用组织的 OpenID Connect 身份登录；控制台不会持久化访问令牌。':
    'Sign in with your organization OpenID Connect identity; the console does not persist access tokens.',
  '使用组织身份登录': 'Sign in with organization identity',
  '访问令牌只保存在当前页面内存中；刷新或关闭页面后需要重新建立会话。':
    'Access tokens are stored only in current page memory; refreshing or closing the page requires a new session.',

  '配置兼容 API Key': 'Configure compatibility API Key',
  '密钥只保存在当前浏览器标签页会话中；刷新会保留，关闭标签页或点击清除后移除，不写入 localStorage、URL 或日志。':
    'The key is stored only in the current browser tab session; refresh keeps it, closing the tab or clearing removes it, and it is not written to localStorage, URLs, or logs.',
  '输入 X-API-Key': 'Enter X-API-Key',
  '清除当前密钥': 'Clear current key',
  '应用': 'Apply',
  '请输入 API Key': 'Please enter an API Key',
  'API Key 过长': 'API Key is too long',

  '该能力尚未开放': 'This capability is not available yet',
  '当前仅展示已接入的受控控制台能力。': 'Only connected controlled console capabilities are currently shown.',
  '暂无数据': 'No data',
  '页面渲染失败': 'Page rendering failed',
  '错误已被隔离，刷新后可重新加载。': 'The error was isolated. Refresh to load the page again.',
  '刷新页面': 'Refresh page',
  '正在加载…': 'Loading…',
  '数据加载失败': 'Data loading failed',
  '重试': 'Retry',
  '暂无任务': 'No tasks',

  '身份与权限': 'Identity and Access',
  '智能体与技能': 'Agents and Skills',
  '授权资产': 'Authorized Assets',
  '审计中心': 'Audit Center',
  '漏洞案件': 'Vulnerability Cases',
  '综合态势': 'Overview',
  'AI 评测': 'AI Evaluation',
  '发布治理': 'Release Governance',
  '知识库': 'Knowledge Base',
  '模型管理': 'Model Management',
  '策略审批': 'Policy and Approval',
  '报告中心': 'Report Center',
  '沙箱中心': 'Sandbox Center',
  '系统状态': 'System Status',
  '任务中心': 'Task Center',
  '验证中心': 'Validation Center',

  '汇总任务、模型、策略和验证工作流的控制台入口。':
    'Console entry point for tasks, models, policies, and validation workflows.',
  '安全边界已启用': 'Security boundaries are enabled',
  '资产探测、沙箱运行和验证执行不会从前端直接触发；所有高风险动作必须走后端策略、审批和审计。':
    'Asset probing, sandbox runs, and validation execution are not triggered directly from the frontend; all high-risk actions must go through backend policy, approval, and audit.',
  '任务总数': 'Total tasks',
  '运行中': 'Running',
  '已成功': 'Succeeded',
  '待审批': 'Pending approval',
  '任务状态分布': 'Task status distribution',
  '正在加载图表…': 'Loading chart…',
  '任务状态分布图': 'Task status distribution chart',

  '身份、租户与权限': 'Identity, Tenant, and Access',
  '权限和数据范围由服务端会话返回；前端只做界面裁剪，后端仍会再次校验。':
    'Permissions and data scope come from the server session; the frontend only trims the interface and the backend still enforces checks.',
  '正在解析服务端权限…': 'Resolving server-side permissions…',
  '当前项目': 'Current project',
  '选择项目上下文': 'Select project context',
  'OIDC + 数据范围 RBAC 已生效': 'OIDC + data-scoped RBAC is active',
  '浏览器令牌只保存在内存；租户和项目权限由 API 端继续强制执行。':
    'Browser tokens are stored only in memory; tenant and project permissions remain enforced by the API.',
  '租户角色': 'Tenant roles',
  '有效权限': 'Effective permissions',
  '可见项目': 'Visible projects',
  '当前会话': 'Current session',
  '用户名': 'Username',
  '租户状态': 'Tenant status',
  '用户 ID': 'User ID',
  '租户 ID': 'Tenant ID',
  '租户': 'Tenant',
  '名称': 'Name',
  '标识': 'Slug',
  '版本': 'Version',
  '租户成员': 'Tenant members',
  '暂无成员': 'No members',
  '角色与显式权限': 'Roles and explicit permissions',
  '暂无角色': 'No roles',
  '最近审计事件': 'Recent audit events',
  '暂无审计事件': 'No audit events',

  '任务列表': 'Task list',
  '没有符合条件的任务': 'No matching tasks',
  '查看': 'View',
  '返回任务中心': 'Back to Task Center',
  '任务投影': 'Task projection',
  '目标': 'Target',
  '意图': 'Intent',
  '审批': 'Approval',
  '范围 ID': 'Scope ID',
  '更新时间': 'Updated',
  '实时事件': 'Live events',
  '暂无事件': 'No events',
  '事件流 已连接': 'Event stream connected',
  '事件流 已关闭': 'Event stream closed',

  '智能体与技能管理': 'Agents and Skills Management',
  '展示已注册智能体、工作流和技能的职责、风险、预算与启用状态。':
    'Shows registered agents, workflows, and skills with responsibilities, risks, budgets, and enablement state.',
  '智能体': 'Agents',
  '工作流': 'Workflows',
  '技能': 'Skills',
  '风险': 'Risk',
  'Token 预算': 'Token budget',
  '超时秒数': 'Timeout seconds',
  '阶段数': 'Stages',
  '执行器': 'Executor',
  '需要审批': 'Requires approval',
  '启用状态': 'Enabled',
  '状态': 'Status',
  '启用': 'Enabled',
  '停用': 'Disabled',
  '是': 'Yes',
  '否': 'No',

  '当前前端只展示已进入任务账本的授权目标和 scope 绑定，不暴露兼容资产探测入口。':
    'The frontend only shows authorized targets already in the task ledger and their scope bindings; compatibility asset probing is not exposed.',
  '默认不连接互联网真实目标': 'No default connection to real Internet targets',
  '资产探测、端口访问和验证步骤必须经过范围、策略、审批和审计；未在契约中开放的执行能力不会在前端伪造。':
    'Asset probing, port access, and validation steps must pass scope, policy, approval, and audit; execution capabilities not exposed by the contract are not faked in the frontend.',
  '任务目标': 'Task targets',
  '范围绑定': 'Scope bindings',
  '排除能力': 'Excluded capabilities',
  '任务授权目标': 'Task authorized targets',
  '任务': 'Task',
  '授权范围': 'Authorized scope',
  '系统排除项': 'System exclusions',
  '能力': 'Capability',
  '说明': 'Description',

  '按时间展示策略、审批、任务、验证和发布动作的审计轨迹。':
    'Shows policy, approval, task, validation, and release audit trails by time.',
  '时间': 'Time',
  '操作者': 'Actor',
  '动作': 'Action',
  '资源': 'Resource',
  '结果': 'Result',
  '追踪 ID': 'Trace ID',
  '审计中心需要 OIDC 模式': 'Audit Center requires OIDC mode',
  '当前是 API Key 兼容模式，后端不会开放租户级审计事件接口；请切换到 OIDC 模式后查看完整审计。':
    'The console is currently using API Key compatibility mode, so tenant-scoped audit events are not exposed by the backend. Switch to OIDC mode to view the full audit trail.',

  '把验证结果收敛为案件、发现项、修复建议、复测和最终处置记录。':
    'Consolidates validation results into cases, findings, remediation proposals, retests, and final dispositions.',
  '创建案件': 'Create case',
  '标题': 'Title',
  '严重性': 'Severity',
  '优先级': 'Priority',
  '来源': 'Source',
  '创建': 'Create',
  '案件': 'Case',
  '项目': 'Project',
  '负责人': 'Owner',
  '创建时间': 'Created',
  '案件详情': 'Case details',
  '维护案件状态、发现项、修复建议、复测请求和人工处置。':
    'Maintain case status, findings, remediation proposals, retest requests, and manual disposition.',
  '案件概览': 'Case overview',
  '受影响资产': 'Affected asset',
  '来源类型': 'Source type',
  '当前版本': 'Current version',
  '切换状态': 'Change status',
  '关闭案件': 'Close case',
  '发现项': 'Findings',
  '修复': 'Remediation',
  '复测': 'Retest',
  '人工处置': 'Manual disposition',
  '添加发现项': 'Add finding',
  '添加建议': 'Add proposal',
  '记录实现': 'Record implementation',
  '复测入队': 'Queue retest',
  '人工确认': 'Manual confirmation',
  '证据强度': 'Evidence strength',
  '修复建议': 'Remediation proposal',
  '决策': 'Decision',
  '理由': 'Reason',
  '实现': 'Implementation',
  '原验证': 'Original validation',
  '复测验证': 'Retest validation',
  '对比结论': 'Comparison conclusion',
  '人工结论': 'Manual conclusion',

  'AI 评测治理': 'AI Evaluation Governance',
  '管理数据集版本、运行基线和候选变体、比较回归，并要求人工提升决策。':
    'Manage dataset versions, run baseline and candidate variants, compare regressions, and require human promotion decisions.',
  '确定性离线评测': 'Deterministic offline evaluation',
  '创建示例运行': 'Create sample run',
  '创建带版本的套件、数据集、显式真值用例、基线变体、候选变体、指标结果、回归对比和门禁结果。':
    'Creates a versioned suite, dataset, explicit ground-truth case, baseline variant, candidate variant, metric results, regression comparison, and gate result.',
  '该流程不会引入新的验证模板，也不会执行 Shell。':
    'This flow does not introduce new validation templates or execute shell commands.',
  '评测运行': 'Evaluation runs',
  '运行': 'Run',
  '类型': 'Type',
  '门禁': 'Gate',
  '配置哈希': 'Config hash',
  '评测套件': 'Evaluation suites',
  '套件': 'Suite',
  '评测运行详情': 'Evaluation run detail',
  '展示数据集、变体、指标、回归对比、安全违规、人工复核和提升决策。':
    'Shows datasets, variants, metrics, regression comparison, security violations, human reviews, and promotion decisions.',
  '运行身份': 'Run identity',
  '数据集': 'Dataset',
  '开始时间': 'Started',
  '结束时间': 'Finished',
  '变体配置矩阵': 'Variant configuration matrix',
  '角色': 'Role',
  '快照': 'Snapshot',
  '指标计分卡': 'Metric scorecard',
  '变体': 'Variant',
  '指标': 'Metric',
  '类别': 'Category',
  '数值': 'Value',
  '单位': 'Unit',
  '基线对比与门禁': 'Baseline comparison and gates',
  '安全门禁': 'Security gate',
  '改善指标': 'Improved metrics',
  '回退指标': 'Regressed metrics',
  '失败门禁': 'Failed gates',
  '成本变化': 'Cost change',
  '延迟变化': 'Latency change',
  '暂无对比结果。': 'No comparison result yet.',
  '失败项与安全违规': 'Failures and security violations',
  '失败用例': 'Failed cases',
  '用例': 'Case',
  '原因': 'Reason',
  '安全违规': 'Security violations',
  '成本与延迟': 'Cost and latency',
  '人工复核与提升': 'Human review and promotion',
  '复核决策': 'Review decision',
  '备注': 'Notes',
  '记录复核': 'Record review',
  '提升决策': 'Promotion decision',
  '目标环境': 'Target environment',
  '记录决策': 'Record decision',

  '面向 CVE 记录、内部指引、任务证据和历史发现的权限感知检索。':
    'Permission-aware search across CVE records, internal guidance, task evidence, and historical findings.',
  '混合检索': 'Hybrid search',
  '查询内容': 'Query',
  '请输入至少两个字符。': 'Enter at least two characters.',
  '搜索': 'Search',
  '返回条数': 'Result count',
  '密级过滤': 'Classification filter',
  '公开': 'Public',
  '内部': 'Internal',
  '受限': 'Restricted',
  '暂无结果': 'No results',

  '基于生成的 API 客户端查看供应商清单、健康状态、可路由模型目录和调用审计。':
    'Uses the generated API client to show providers, health status, routable model catalog, and invocation audit.',
  '凭据由后端托管': 'Credentials are managed by the backend',
  '控制台不会展示或持久化模型明文凭据。': 'The console does not show or persist plaintext model credentials.',
  '模型': 'Models',
  '就绪供应商': 'Ready providers',
  '最近调用': 'Recent invocations',
  '供应商': 'Provider',
  '基础地址': 'Base URL',
  '模型目录': 'Model catalog',
  '上下文窗口': 'Context window',
  '调用记录': 'Invocations',
  'Token 数': 'Token count',
  '成本估算': 'Cost estimate',

  '手工预评估策略命中结果；真正执行仍必须由后端策略执行点、范围和审批状态再次校验。':
    'Manually pre-evaluate policy decisions; real execution must still be rechecked by the backend policy enforcement point, scope, and approval state.',
  '策略判定不授予执行能力': 'Policy decisions do not grant execution capability',
  '本页面只产生可审计的 policy_decision。批准验证计划或 allow 决策都不会绕过后端执行边界。':
    'This page only creates an auditable policy_decision. Approved validation plans or allow decisions do not bypass backend execution boundaries.',
  '策略预评估': 'Policy preflight',
  '资产探测（asset.probe）': 'Asset probe (asset.probe)',
  '沙箱运行（sandbox.run）': 'Sandbox run (sandbox.run)',
  '任务执行（task.execute）': 'Task execution (task.execute)',
  '上下文恢复（context.restore）': 'Context restore (context.restore)',
  '知识检索（rag.search）': 'Knowledge search (rag.search)',
  '端口': 'Port',
  '破坏性': 'Destructive',
  '评估': 'Evaluate',
  '策略结果': 'Policy result',
  '近期策略审计': 'Recent policy audit',
  '暂无策略审计事件': 'No policy audit events',
  '审计事件需要 OIDC 模式': 'Audit events require OIDC mode',
  '当前 API Key 兼容模式仍可执行策略预评估，但不会读取租户级审计事件。':
    'Policy preflight remains available in API Key compatibility mode, but tenant-scoped audit events are not read.',

  '发布候选详情': 'Release candidate detail',
  '展示冻结产物身份、门禁评估、审批、环境提升、漂移、回滚和合规证据。':
    'Shows frozen artifact identity, gate evaluation, approvals, promotion, drift, rollback, and compliance evidence.',
  '冻结发布身份': 'Frozen release identity',
  '候选': 'Candidate',
  '源码提交': 'Source commit',
  '镜像摘要': 'Image digest',
  'SBOM 摘要': 'SBOM digest',
  '来源证明摘要': 'Provenance digest',
  '签名摘要': 'Signature digest',
  'Helm 图表摘要': 'Helm chart digest',
  '冻结哈希': 'Freeze hash',
  '发布门禁': 'Release gates',
  '环境': 'Environment',
  '评估预发布': 'Evaluate staging',
  '生成合规包': 'Generate compliance package',
  '审批、例外与环境提升': 'Approvals, exceptions, and promotion',
  '填写审批原因': 'Enter approval reason',
  '记录审批': 'Record approval',
  '提升环境': 'Promotion environment',
  '金丝雀比例': 'Canary percentage',
  '提升': 'Promote',
  '例外门禁': 'Exception gate',
  '范围': 'Scope',
  '填写例外原因': 'Enter exception reason',
  '申请例外': 'Request exception',
  '供应链证据': 'Supply-chain evidence',
  'SBOM 文档': 'SBOM documents',
  '来源证明': 'Provenance statements',
  '签名记录': 'Signature records',
  '安全扫描': 'Security scans',
  '许可证扫描': 'License scans',
  '产物仓库': 'Artifact repository',
  '部署与漂移': 'Deployments and drift',
  '检测漂移': 'Detect drift',
  '回滚最新部署': 'Rollback latest deployment',
  '摘要': 'Digest',
  '供应链发布候选': 'Supply-chain release candidate',
  '创建示例发布候选': 'Create sample release candidate',
  '示例流程只登记一个包含 SBOM、来源证明、签名、漏洞扫描和许可证扫描元数据的不可变容器摘要，': 'The sample flow registers one immutable container digest with SBOM, provenance, signature, vulnerability scan, and license scan metadata, ',
  '然后冻结发布候选；不会执行构建、扫描器、Shell、PoC 或部署。': 'then freezes a release candidate; it does not execute a build, scanner, shell, PoC, or deployment.',
  '发布候选': 'Release candidates',
  '已登记产物': 'Registered artifacts',
  '产物': 'Artifact',

  '展示已生成报告和证据产物，当前前端不提供未授权导出。':
    'Shows generated reports and evidence artifacts; unauthorized export is not exposed in the frontend.',
  '暂无可用于报告的任务': 'No tasks are available for reporting',
  '请先在任务中心创建任务；任务产生证据后，报告中心会显示证据准备度。':
    'Create a task in Task Center first; once the task produces evidence, Report Center will show evidence readiness.',
  '报告': 'Reports',
  '报告类型': 'Report type',
  '生成时间': 'Generated',
  '下载': 'Download',

  '查看任务执行记录和验证沙箱边界；控制台不会运行模型生成的命令。':
    'Shows task execution records and validation sandbox boundaries; the console does not run model-generated commands.',
  '展示受控验证沙箱的运行状态、资源边界和执行证据入口。':
    'Shows controlled validation sandbox status, resource boundaries, and execution evidence entry points.',
  '暂无可查看的任务': 'No tasks are available to inspect',
  '请先创建任务；任务产生执行记录后，沙箱中心会展示验证沙箱和任务执行账本。':
    'Create a task first; after it produces execution records, Sandbox Center will show validation sandboxes and the task execution ledger.',
  '验证沙箱': 'Validation sandboxes',
  '沙箱': 'Sandbox',
  '工作节点': 'Worker',
  'CPU 限制': 'CPU limit',
  '内存限制': 'Memory limit',
  'PID 限制': 'PID limit',
  '只读根文件系统': 'Read-only root filesystem',
  '特权模式': 'Privileged mode',
  '主机网络': 'Host network',
  'Docker Socket': 'Docker socket',

  '系统运行状态': 'System operations',
  '展示高可用、容量、证据一致性、备份与灾难恢复状态。':
    'Shows high availability, capacity, evidence consistency, backup, and disaster recovery status.',
  '隐藏原始 JSON': 'Hide raw JSON',
  '显示原始 JSON': 'Show raw JSON',
  '缺少 GitHub 权威隔离运行时证据，生产就绪仍为否。':
    'Authoritative GitHub isolated runtime evidence is missing; production readiness remains no.',
  '所有关键门禁均具备运行时证据。': 'All critical gates have runtime evidence.',
  '控制平面实例': 'Control-plane instances',
  '工作节点数量': 'Workers',
  '待处理队列': 'Pending queue',
  '证据状态': 'Evidence status',
  '生产就绪': 'Production ready',
  '可追溯项': 'Traceability items',
  '验收与交付': 'Acceptance and delivery',
  '工程基线': 'Engineering baseline',
  '受控验证执行平面': 'Controlled validation execution plane',
  '修复闭环': 'Remediation lifecycle',
  '高可用运行时就绪': 'High-availability runtime readiness',
  '交付闭环': 'Delivery closure',
  '权威隔离运行时': 'Authoritative isolated runtime',
  '发布治理门禁': 'Release governance gate',
  'SBOM、签名与来源证明': 'SBOM, signature, and provenance',
  '确定性基线': 'Deterministic baselines',
  '数据库迁移': 'Database migrations',
  '前端构建': 'Frontend build',
  '已知限制复核': 'Known limitations review',
  '工程与运行基线': 'Engineering and runtime baseline',
  'API 优先的控制平面、身份权限、审计、模型网关、知识上下文和确定性基线。':
    'API-first control plane, identity and access, audit, model gateway, knowledge context, and deterministic baselines.',
  '已审批验证计划可通过受控工作节点、沙箱和证据闭环创建幂等执行。':
    'Approved validation plans can create idempotent executions through controlled workers, sandboxes, and evidence loops.',
  '已确认案件会经过修复建议、决策、实施、复测、对比、报告和关闭流程。':
    'Confirmed cases flow through remediation proposal, decision, implementation, retest, comparison, reporting, and closure.',
  '版本化评测套件、数据集、确定性指标、回归对比、复核和提升门禁。':
    'Versioned evaluation suites, datasets, deterministic metrics, regression comparisons, reviews, and promotion gates.',
  '高可用、扩缩容、就绪检查、备份恢复、混沌演练和运行时门禁。':
    'High availability, scaling, readiness checks, backup and restore, chaos drills, and runtime gates.',
  '发布产物、SBOM、来源证明、签名、扫描门禁、环境提升、回滚、漂移和合规证据包。':
    'Release artifacts, SBOM, provenance, signatures, scan gates, promotions, rollback, drift, and compliance evidence packages.',
  '最终验收、升级回滚矩阵、数据治理、密钥生命周期证据、合规映射、交付包和生产就绪门禁。':
    'Final acceptance, upgrade and rollback matrix, data governance, secret lifecycle evidence, compliance mapping, delivery package, and production readiness gate.',
  '参考运行时保留现有接口可用性。':
    'Existing endpoints remain available behind the reference runtime.',
  '当前检出版本缺少已验证的 GitHub 隔离运行时产物。':
    'Verified GitHub isolated runtime artifacts are missing from this checkout.',
  '确定性基线已作为兼容性门禁跟踪。':
    'Deterministic baselines are tracked as compatibility gates.',
  'AI 评测治理和回归门禁已可用。':
    'AI evaluation governance and regression gates are available.',
  '发布治理已具备，但生产提升仍需等待权威运行时通过。':
    'Release governance is available, but production promotion remains blocked until authoritative runtime passes.',
  '迁移集合包含完整的可逆迁移。':
    'The migration set includes the complete reversible migration chain.',
  '交付路径已纳入版本化 API 合约。':
    'Delivery paths are part of the versioned API contract.',
  'Web 控制台复用现有路由展示状态和交付视图。':
    'The web console reuses existing routes for status and delivery views.',
  '可生成候选交付包；正式交付包仍需要当前 SBOM、签名、来源证明和运行时证据。':
    'Candidate delivery can be generated; the formal package still requires current SBOM, signature, provenance, and runtime evidence.',
  '需求到实现的矩阵已通过 API 和文档暴露。':
    'The requirement-to-implementation matrix is exposed through the API and documentation.',
  '运行验收': 'Run acceptance',
  '生成交付包': 'Generate delivery package',
  '运行时已声明': 'Runtime claimed',
  '运行时未声明': 'Runtime not claimed',
  '支持升级路径': 'Supported upgrade paths',
  '失败关键门禁': 'Failed critical gates',
  '已知限制': 'Known limitations',
  '验收运行失败': 'Acceptance run failed',
  '交付包已生成': 'Delivery package generated',
  '交付包生成失败': 'Delivery package failed',
  '合规证据包已生成': 'Compliance evidence package generated',
  '需求可追溯性': 'Requirement traceability',
  '生产就绪门禁': 'Production readiness gates',
  '关键': 'Critical',
  '非关键': 'Non-critical',
  '数据治理与密钥生命周期': 'Data governance and secret lifecycle',
  '导出租户数据': 'Export tenant data',
  '租户导出清单已生成': 'Tenant export manifest generated',
  '数据导出失败': 'Data export failed',
  '分类': 'Classifications',
  '租户导出': 'Tenant exports',
  '删除请求': 'Deletion requests',
  '生效法律保留': 'Active legal holds',
  '密钥显示': 'Secret display',
  '已脱敏': 'Redacted',
  '交付包内密钥': 'Secrets in delivery',
  '合规控制映射': 'Compliance control mapping',
  '控制映射不等同于认证。': 'Control mapping is not certification.',
  '平台只导出可供审阅的证据映射，不声明外部认证。':
    'The platform exports evidence mappings for review; it does not claim external certification.',
  '声明认证': 'Certification claimed',
  '仅映射': 'Mapping only',
  '运行模式与容量边界': 'Runtime mode and capacity boundaries',
  '数据库': 'Database',
  '队列后端': 'Queue backend',
  '沙箱后端': 'Sandbox backend',
  '证据后端': 'Evidence backend',
  '全局并发': 'Global concurrency',
  '租户并发': 'Tenant concurrency',
  '沙箱容量': 'Sandbox capacity',
  '服务实例': 'Service instances',
  '验证工作节点': 'Validation workers',
  '队列、NATS 与数据库韧性': 'Queue, NATS, and database resilience',
  '就绪': 'Ready',
  '租约中': 'Leased',
  '死信': 'Dead-lettered',
  '队列深度阈值': 'Queue depth threshold',
  'NATS 流': 'NATS stream',
  'NATS 消费者': 'NATS consumer',
  '最大重试次数': 'Max retry attempts',
  '重试基础延迟秒数': 'Retry base delay seconds',
  '数据库连接池上限': 'Database pool cap',
  '公平调度与配额状态': 'Fairness and quota posture',
  '全局运行中': 'Global running',
  '租户数': 'Tenants',
  '项目数': 'Projects',
  '优先级不会绕过审批、范围、策略或资源配额。':
    'Priority never bypasses approval, scope, policy, or resource quota.',
  '证据一致性': 'Evidence consistency',
  '运行检查': 'Run check',
  '证据一致性检查失败': 'Evidence consistency check failed',
  '报告 ID': 'Report ID',
  '修复动作': 'Repair action',
  '备份、灾难恢复与混沌保护': 'Backup, disaster recovery, and chaos guard',
  '备份状态': 'Backup status',
  '最近备份': 'Last backup',
  'RPO 目标': 'RPO target',
  'RTO 目标': 'RTO target',
  '最近演练': 'Last drill',
  '混沌已启用': 'Chaos enabled',
  '可用性边界': 'Availability boundaries',
  '原始运行数据': 'Raw operational payload',
  '正在加载 JSON 查看器…': 'Loading JSON viewer…',
  '暂无上报记录。': 'No records reported.',
  '未报告': 'Not reported',
  '未检查': 'Not checked',
  '未知': 'Unknown',
  '无': 'None',
  '95 分位延迟': '95th percentile latency',

  '只创建、审批和运行预注册验证模板；不接受任意 PoC 或 Shell。':
    'Only creates, approves, and runs pre-registered validation templates; arbitrary PoC or shell is not accepted.',
  '暂无可验证的任务': 'No tasks are available for validation',
  '请先在任务中心创建任务；任务创建后才能起草验证计划、入队执行并查看证据。':
    'Create a task in Task Center first; after a task exists, you can draft validation plans, queue executions, and review evidence.',
  '创建验证计划': 'Create validation plan',
  '模板': 'Template',
  'HTTP 路径': 'HTTP path',
  '期望状态码': 'Expected status code',
  '创建草稿': 'Create draft',
  '验证计划': 'Validation plans',
  '提交': 'Submit',
  '批准': 'Approve',
  '拒绝': 'Reject',
  '执行入队': 'Queue execution',
  '执行实例': 'Executions',
  '取消': 'Cancel',
  '接受证据': 'Accept evidence',
  '事件时间线': 'Event timeline',
  '证据列表': 'Evidence list',
  '文件名': 'Filename',
  '大小': 'Size',
  '人工复核': 'Human review',
  '沙箱状态': 'Sandbox status',
  '策略判定': 'Policy decision',
  '审批状态': 'Approval status',
  '证据': 'Evidence',
};

const PHRASE_REPLACEMENTS: Array<[RegExp, string]> = [
  [/检索结果：/g, 'Search results: '],
  [/分片 #/g, 'chunk #'],
  [/得分 /g, 'score '],
  [/ 项权限/g, ' permissions'],
  [/已脱敏=/g, 'redacted='],
  [/；密钥数量=/g, '; secret_count='],
  [/，位置：/g, ' at '],
  [/ 个控制项；/g, ' controls; '],
  [/API：/g, 'APIs: '],
  [/；迁移：/g, '; migrations: '],
  [/差距：/g, 'Gap: '],
  [/兼容模式：/g, 'Compatibility mode: '],
  [/生产就绪：/g, 'Production readiness: '],
  [/验收运行：/g, 'Acceptance run: '],
  [/预发布门禁已评估。/g, 'Staging gates evaluated.'],
  [/审批已记录。/g, 'Approval recorded.'],
  [/例外已记录。/g, 'Exception recorded.'],
  [/环境提升已记录。/g, 'Promotion recorded.'],
  [/合规包已生成。/g, 'Compliance package generated.'],
  [/回滚已记录。/g, 'Rollback recorded.'],
  [/漂移报告已记录。/g, 'Drift report recorded.'],
  [/评测运行已创建。/g, 'Evaluation run created.'],
  [/发布候选已创建。/g, 'Release candidate created.'],
  [/案件已创建。/g, 'Case created.'],
  [/案件状态已更新。/g, 'Case status updated.'],
  [/发现项已保存。/g, 'Finding saved.'],
  [/修复建议已保存。/g, 'Remediation proposal saved.'],
  [/决策已保存。/g, 'Decision saved.'],
  [/修复实现已记录。/g, 'Implementation recorded.'],
  [/复测已入队。/g, 'Retest queued.'],
  [/处置已记录。/g, 'Disposition recorded.'],
  [/案件已关闭。/g, 'Case closed.'],
  [/验证计划已创建。/g, 'Validation plan created.'],
  [/验证计划已提交。/g, 'Validation plan submitted.'],
  [/验证计划已复核。/g, 'Validation plan reviewed.'],
  [/执行已入队。/g, 'Execution queued.'],
  [/执行已取消。/g, 'Execution cancelled.'],
  [/执行已重试。/g, 'Execution retried.'],
  [/复核已记录。/g, 'Review recorded.'],
  [/从验证控制台批准/g, 'approved from validation console'],
  [/从验证控制台拒绝/g, 'rejected from validation console'],
  [/从验证控制台接受证据/g, 'accepted evidence from validation console'],
  [/从验证控制台拒绝证据/g, 'rejected evidence from validation console'],
  [/已准备进入受控复测。/g, 'Ready for controlled retest.'],
  [/Web 评测/g, 'Web evaluation'],
  [/回归数据集/g, 'Regression dataset'],
  [/示例产物/g, 'Sample artifact'],
  [/示例发布候选/g, 'Sample release candidate'],
  [/权威隔离运行时/g, 'Authoritative isolated runtime'],
  [/发布治理门禁/g, 'Release governance gate'],
  [/SBOM、签名与来源证明/g, 'SBOM, signature, and provenance'],
  [/确定性基线/g, 'Deterministic baselines'],
  [/工程基线/g, 'Engineering baseline'],
  [/交付闭环/g, 'Delivery closure'],
  [/从 Web 控制台创建的确定性评测套件。/g, 'Deterministic evaluation suite created from the web console.'],
  [/用于回归门禁的版本化真值数据集。/g, 'Versioned ground truth dataset for regression gates.'],
  [/控制台操作者请求回滚/g, 'operator requested rollback from console'],
];

const EXACT_EN_TO_ZH: Record<string, string> = Object.fromEntries(
  Object.entries(EXACT_ZH_TO_EN).map(([zh, en]) => [en, zh]),
);

Object.assign(EXACT_EN_TO_ZH, {
  'Organization identity / OIDC': '组织身份认证 / OIDC',
  'API Key authentication': 'API Key 认证',
  'Configure API key': '配置 API Key',
  'Agents / Skills': '智能体与技能',
  Access: '身份与权限',
  Assets: '授权资产',
  Audit: '审计中心',
  Cases: '漏洞案件',
  Evaluations: 'AI 评测',
  Releases: '发布治理',
  Knowledge: '知识库',
  Models: '模型管理',
  Policies: '策略审批',
  Reports: '报告中心',
  Sandboxes: '沙箱中心',
  System: '系统状态',
  Tasks: '任务中心',
  Validation: '验证中心',
});

const textOriginals = new WeakMap<Text, string>();
const attributeOriginals = new WeakMap<Element, Map<string, string>>();
const ATTRIBUTES = ['aria-label', 'placeholder', 'title'] as const;

function translateUiText(value: string, locale: AppLocale): string {
  const match = value.match(/^(\s*)([\s\S]*?)(\s*)$/);
  const prefix = match?.[1] ?? '';
  const body = match?.[2] ?? value;
  const suffix = match?.[3] ?? '';
  if (locale === 'zh-CN') {
    const compactBody = body.replace(/\s+/g, '');
    const restored = EXACT_EN_TO_ZH[body] ?? EXACT_EN_TO_ZH[compactBody] ?? body;
    return `${prefix}${restored}${suffix}`;
  }
  if (!CJK_RE.test(body)) return value;
  const compact = body.replace(/\s+/g, '');
  let translated = EXACT_ZH_TO_EN[body] ?? EXACT_ZH_TO_EN[compact] ?? body;
  for (const [pattern, replacement] of PHRASE_REPLACEMENTS) {
    translated = translated.replace(pattern, replacement);
  }
  return `${prefix}${translated}${suffix}`;
}

function shouldSkip(element: Element | null): boolean {
  return Boolean(element?.closest('script, style, textarea, code, pre, .monaco-editor, [data-no-i18n]'));
}

function translateTextNode(node: Text, locale: AppLocale) {
  if (shouldSkip(node.parentElement)) return;
  const current = node.nodeValue ?? '';
  const stored = textOriginals.get(node);
  if (locale === 'zh-CN') {
    if (stored !== undefined && current !== stored) node.nodeValue = stored;
    if (stored === undefined) {
      const translated = translateUiText(current, locale);
      if (translated !== current) node.nodeValue = translated;
    }
    textOriginals.delete(node);
    return;
  }
  const original = stored === undefined || CJK_RE.test(current) ? current : stored;
  textOriginals.set(node, original);
  const translated = translateUiText(original, locale);
  if (translated !== current) node.nodeValue = translated;
}

function translateAttributes(element: Element, locale: AppLocale) {
  if (shouldSkip(element)) return;
  for (const attribute of ATTRIBUTES) {
    const current = element.getAttribute(attribute);
    if (!current) continue;
    const storedByAttribute = attributeOriginals.get(element);
    const stored = storedByAttribute?.get(attribute);
    if (locale === 'zh-CN') {
      if (stored !== undefined && current !== stored) element.setAttribute(attribute, stored);
      if (stored === undefined) {
        const translated = translateUiText(current, locale);
        if (translated !== current) element.setAttribute(attribute, translated);
      }
      storedByAttribute?.delete(attribute);
      continue;
    }
    const original = stored === undefined || CJK_RE.test(current) ? current : stored;
    if (!attributeOriginals.has(element)) attributeOriginals.set(element, new Map());
    attributeOriginals.get(element)?.set(attribute, original);
    const translated = translateUiText(original, locale);
    if (translated !== current) element.setAttribute(attribute, translated);
  }
}

function applyLocale(root: ParentNode, locale: AppLocale) {
  const documentRef = root instanceof Document ? root : document;
  const walker = documentRef.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let node = walker.nextNode();
  while (node) {
    translateTextNode(node as Text, locale);
    node = walker.nextNode();
  }
  if (root instanceof Element) translateAttributes(root, locale);
  root.querySelectorAll?.('*').forEach((element) => translateAttributes(element, locale));
}

function observeLocale(locale: AppLocale) {
  if (typeof document === 'undefined' || !document.body) return undefined;
  let scheduled = false;
  const run = () => {
    scheduled = false;
    applyLocale(document.body, locale);
  };
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    window.setTimeout(run, 0);
  };
  run();
  const observer = new MutationObserver(schedule);
  observer.observe(document.body, {
    attributes: true,
    attributeFilter: [...ATTRIBUTES],
    childList: true,
    characterData: true,
    subtree: true,
  });
  return () => observer.disconnect();
}

export function LocalizedTextRuntime() {
  const locale = usePreferencesStore((state) => state.locale);

  useEffect(() => observeLocale(locale), [locale]);

  return null;
}
