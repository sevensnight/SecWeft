import { useMutation, useQuery } from '@tanstack/react-query';
import { Alert, Button, Card, Descriptions, List, Space, Statistic, Tag, Typography } from 'antd';
import { lazy, Suspense, useState } from 'react';
import type { SystemResilience } from '@vulnlab/shared-types';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnBoolean, cnLabel } from '../../../i18n/formatters';
import {
  exportTenantData,
  generateComplianceEvidencePackage,
  generateDeliveryPackage,
  runEnterpriseAcceptance,
} from '../../../services/acceptance';
import { runEvidenceConsistencyCheck } from '../../../services/api';
import {
  acceptanceRequirementsQuery,
  acceptanceStatusQuery,
  complianceControlsQuery,
  productionReadinessQuery,
  systemRequirementsQuery,
  systemResilienceQuery,
} from '../api/queries';

const MonacoEditor = lazy(() => import('@monaco-editor/react'));

type JsonRecord = Record<string, unknown>;

const EMPTY_RESILIENCE: SystemResilience = {
  version: '未报告',
  mode: {},
  service_instances: [],
  workers: [],
  queue: {},
  fairness: {},
  capacity: {},
  database: {},
  nats: {},
  evidence_consistency: null,
  backup: {},
  disaster_recovery: {},
  chaos: {},
  boundaries: [],
};

function asRecord(value: unknown): JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

function text(value: unknown, fallback = '未报告'): string {
  if (typeof value === 'string' && value.length > 0) return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
}

function cnText(value: unknown, fallback = '未报告'): string {
  if (typeof value === 'boolean') return cnBoolean(value);
  return cnLabel(text(value, fallback), fallback);
}

function numberValue(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function records(value: unknown): JsonRecord[] {
  return Array.isArray(value) ? value.map(asRecord) : [];
}

function statusColor(value: unknown): string {
  const normalized = text(value, '').toLowerCase();
  if (['healthy', 'ready', 'running', 'active', 'allowed'].includes(normalized)) return 'green';
  if (['warning', 'degraded', 'leased', 'pending'].includes(normalized)) return 'gold';
  if (['failed', 'blocked', 'inconsistent', 'dead_lettered', 'unavailable'].includes(normalized)) {
    return 'red';
  }
  return 'blue';
}

const IDENTIFIER_LABELS: Record<string, string> = {
  'P0-P8.ENTERPRISE_BASELINE': '工程基线',
  'P9.CONTROLLED_EXECUTION_PLANE': '受控验证执行平面',
  'P10.REMEDIATION_LIFECYCLE': '修复闭环',
  'P11.AI_EVALUATION_GOVERNANCE': 'AI 评测治理',
  'P12.HA_RUNTIME_READINESS': '高可用运行时就绪',
  'P13.RELEASE_GOVERNANCE': '发布治理',
  'P14.ENTERPRISE_DELIVERY': '交付闭环',
  all_migrations: '数据库迁移',
  backup_readiness: '备份就绪',
  configuration_policy: '配置策略',
  container_scan: '容器扫描',
  frontend_build: '前端构建',
  helm_lint: 'Helm 静态检查',
  helm_policy: 'Helm 策略',
  known_limitations_review: '已知限制复核',
  license_policy: '许可证策略',
  migration_compatibility: '迁移兼容性',
  openapi_snapshot: 'OpenAPI 快照',
  provenance_valid: '来源证明有效',
  requirement_traceability: '需求可追溯性',
  rollback_readiness: '回滚就绪',
  sbom_generated: 'SBOM 已生成',
  sbom_signature_provenance: 'SBOM、签名与来源证明',
  secret_scan: '密钥扫描',
  signature_valid: '签名有效',
  source_commit_exists: '源码提交存在',
  source_tree_clean: '源码树干净',
  unit_integration_e2e: '单元、集成与端到端测试',
  vulnerability_policy: '漏洞策略',
  p0_p12_baseline: '工程与运行基线',
  p0_p13_baselines: '确定性基线',
  p11_evaluation_gate: 'AI 评测门禁',
  p11_evaluation_gates: 'AI 评测门禁',
  p12_authoritative_runtime: '权威隔离运行时',
  p13_release_gate: '发布治理门禁',
};

const SYSTEM_TEXT_LABELS: Record<string, string> = {
  'API-first enterprise control plane, identity, RBAC, audit, model gateway, knowledge context, and deterministic baselines.':
    'API 优先的控制平面、身份权限、审计、模型网关、知识上下文和确定性基线。',
  'Approved validation plans can create idempotent executions through the controlled worker, sandbox, and evidence loop.':
    '已审批验证计划可通过受控工作节点、沙箱和证据闭环创建幂等执行。',
  'Confirmed cases flow through remediation proposal, decision, implementation, retest, comparison, reporting, and closure.':
    '已确认案件会经过修复建议、决策、实施、复测、对比、报告和关闭流程。',
  'Versioned evaluation suites, datasets, deterministic metrics, regression comparisons, reviews, and promotion gates.':
    '版本化评测套件、数据集、确定性指标、回归对比、复核和提升门禁。',
  'High availability, scaling, readiness, backup/restore, chaos drills, and runtime gates.':
    '高可用、扩缩容、就绪检查、备份恢复、混沌演练和运行时门禁。',
  'Release artifacts, SBOM, provenance, signatures, scan gates, promotions, rollback, drift, and compliance evidence package.':
    '发布产物、SBOM、来源证明、签名、扫描门禁、环境提升、回滚、漂移和合规证据包。',
  'Final enterprise acceptance, upgrade/rollback matrix, data governance, secret lifecycle evidence, compliance mapping, delivery package, and production readiness gate.':
    '最终验收、升级回滚矩阵、数据治理、密钥生命周期证据、合规映射、交付包和生产就绪门禁。',
  'existing endpoints remain available behind the reference runtime':
    '参考运行时保留现有接口可用性。',
  'No verified GitHub isolated runtime run artifacts are present in this checkout.':
    '当前检出版本缺少已验证的 GitHub 隔离运行时产物。',
  'P0-P13 deterministic baselines are tracked as compatibility gates.':
    '确定性基线已作为兼容性门禁跟踪。',
  'P11 evaluation governance and regression gates are available.':
    'AI 评测治理和回归门禁已可用。',
  'Release governance exists, but production promotion remains blocked until authoritative runtime passes.':
    '发布治理已具备，但生产提升仍需等待权威运行时通过。',
  'Migration set includes 0001 through 0014 with reversible down migrations.':
    '迁移集合包含完整的可逆迁移。',
  'P14 paths are part of the versioned API contract.':
    '交付路径已纳入版本化 API 合约。',
  'The web console reuses existing routes for P14 status and delivery views.':
    'Web 控制台复用现有路由展示状态和交付视图。',
  'Candidate delivery can be generated, but formal package requires current SBOM, signature, provenance, and runtime evidence.':
    '可生成候选交付包；正式交付包仍需要当前 SBOM、签名、来源证明和运行时证据。',
  'Requirement-to-implementation matrix is exposed through API and documentation.':
    '需求到实现的矩阵已通过 API 和文档暴露。',
};

function displayIdentifier(value: unknown, fallback = '-'): string {
  const raw = text(value, fallback);
  return IDENTIFIER_LABELS[raw] ?? cnLabel(raw, raw);
}

function displayIdentifierList(values: string[]): string {
  const labels = values.map((value) => displayIdentifier(value)).filter(Boolean);
  return labels.length > 0 ? labels.join('、') : '无';
}

function displayVersion(value: unknown): string {
  return text(value).replace(/-p\d+\b/gi, '');
}

function displayUpgradePath(value: string): string {
  return value.replace(/-p\d+\b/gi, '').replace('->', '→');
}

function displaySystemText(value: unknown): string {
  const raw = text(value);
  return SYSTEM_TEXT_LABELS[raw] ?? raw;
}

function recordList(recordsValue: JsonRecord[], primary: string, secondary: string) {
  if (recordsValue.length === 0) {
    return <Typography.Text type="secondary">暂无上报记录。</Typography.Text>;
  }
  return (
    <List
      dataSource={recordsValue}
      renderItem={(item, index) => (
        <List.Item>
          <List.Item.Meta
            title={
              <Space wrap>
                <Typography.Text strong>{text(item[primary], `record-${index + 1}`)}</Typography.Text>
                <Tag color={statusColor(item.status)}>{cnText(item.status, '未知')}</Tag>
              </Space>
            }
            description={
              <Typography.Text type="secondary">
                {secondary}: {text(item[secondary], '未报告')}
              </Typography.Text>
            }
          />
        </List.Item>
      )}
    />
  );
}

export function SystemPage() {
  const requirementsQuery = useQuery(systemRequirementsQuery());
  const resilienceQuery = useQuery(systemResilienceQuery());
  const acceptanceRequirements = useQuery(acceptanceRequirementsQuery());
  const acceptanceStatus = useQuery(acceptanceStatusQuery());
  const complianceControls = useQuery(complianceControlsQuery());
  const productionReadiness = useQuery(productionReadinessQuery());
  const evidenceCheck = useMutation({
    mutationFn: () => runEvidenceConsistencyCheck(),
    onSuccess: () => {
      void resilienceQuery.refetch();
    },
  });
  const acceptanceRun = useMutation({
    mutationFn: () =>
      runEnterpriseAcceptance({
        tenant_id: 'system',
        project_id: 'project-alpha',
        scenario_id: 'p14-final-enterprise-acceptance',
        trace_id: crypto.randomUUID().replaceAll('-', ''),
        runtime_evidence: {},
      }),
    onSuccess: () => {
      void acceptanceStatus.refetch();
      void productionReadiness.refetch();
    },
  });
  const deliveryPackage = useMutation({
    mutationFn: () =>
      generateDeliveryPackage({
        tenant_id: 'system',
        project_id: 'project-alpha',
        package_type: 'candidate',
      }),
  });
  const compliancePackage = useMutation({
    mutationFn: () =>
      generateComplianceEvidencePackage({
        tenant_id: 'system',
        project_id: 'project-alpha',
        frameworks: [],
      }),
  });
  const dataExport = useMutation({
    mutationFn: () => exportTenantData({ tenant_id: 'system', project_id: 'project-alpha', format: 'json' }),
  });
  const [showRaw, setShowRaw] = useState(false);

  const resilience = resilienceQuery.data ?? EMPTY_RESILIENCE;
  const mode = asRecord(resilience?.mode);
  const queue = asRecord(resilience?.queue);
  const capacity = asRecord(resilience?.capacity);
  const fairness = asRecord(resilience?.fairness);
  const database = asRecord(resilience?.database);
  const nats = asRecord(resilience?.nats);
  const evidenceConsistency = asRecord(resilience?.evidence_consistency);
  const backup = asRecord(resilience?.backup);
  const disasterRecovery = asRecord(resilience?.disaster_recovery);
  const chaos = asRecord(resilience?.chaos);

  return (
    <section>
      <div className="page-title-row">
        <div>
          <Typography.Title level={2}>系统运行状态</Typography.Title>
          <Typography.Text type="secondary">
            展示高可用、容量、证据一致性、备份与灾难恢复状态。
          </Typography.Text>
        </div>
        <Button onClick={() => setShowRaw((current) => !current)}>
          {showRaw ? '隐藏原始 JSON' : '显示原始 JSON'}
        </Button>
      </div>

      {requirementsQuery.isPending ||
      resilienceQuery.isPending ||
      acceptanceRequirements.isPending ||
      acceptanceStatus.isPending ||
      complianceControls.isPending ||
      productionReadiness.isPending ? (
        <LoadingState />
      ) : null}
      {requirementsQuery.isError ? (
        <QueryErrorState
          error={requirementsQuery.error}
          onRetry={() => void requirementsQuery.refetch()}
        />
      ) : null}
      {resilienceQuery.isError ? (
        <QueryErrorState error={resilienceQuery.error} onRetry={() => void resilienceQuery.refetch()} />
      ) : null}
      {acceptanceStatus.isError ? (
        <QueryErrorState
          error={acceptanceStatus.error}
          onRetry={() => void acceptanceStatus.refetch()}
        />
      ) : null}
      {productionReadiness.isError ? (
        <QueryErrorState
          error={productionReadiness.error}
          onRetry={() => void productionReadiness.refetch()}
        />
      ) : null}

      {requirementsQuery.isSuccess &&
      resilienceQuery.isSuccess &&
      acceptanceRequirements.isSuccess &&
      acceptanceStatus.isSuccess &&
      complianceControls.isSuccess &&
      productionReadiness.isSuccess ? (
        <Space direction="vertical" size="middle" className="full-width">
          <Alert
            showIcon
            type={requirementsQuery.data.p0_migration.legacy_execution_enabled ? 'warning' : 'success'}
            message={`兼容模式：${cnText(requirementsQuery.data.p0_migration.status)}`}
            description={displaySystemText(requirementsQuery.data.p0_migration.compatibility)}
          />
          <Alert
            showIcon
            type={productionReadiness.data.production_ready ? 'success' : 'error'}
            message={`生产就绪：${productionReadiness.data.production_ready ? '就绪' : '阻断'}`}
            description={
              productionReadiness.data.runtime_not_claimed
                ? '缺少 GitHub 权威隔离运行时证据，生产就绪仍为否。'
                : '所有关键门禁均具备运行时证据。'
            }
          />

          <Space wrap size="large">
            <Card>
              <Statistic title="控制平面实例" value={resilience.service_instances.length} />
            </Card>
            <Card>
              <Statistic title="工作节点数量" value={resilience.workers.length} />
            </Card>
            <Card>
              <Statistic title="待处理队列" value={numberValue(queue.pending)} />
            </Card>
            <Card>
              <Statistic
                title="证据状态"
                value={cnText(evidenceConsistency.status, '未检查')}
                valueStyle={{ color: statusColor(evidenceConsistency.status) }}
              />
            </Card>
            <Card>
              <Statistic
                title="生产就绪"
                value={cnBoolean(productionReadiness.data.production_ready)}
                valueStyle={{
                  color: productionReadiness.data.production_ready ? 'green' : 'red',
                }}
              />
            </Card>
            <Card>
              <Statistic
                title="可追溯项"
                value={acceptanceRequirements.data.length}
              />
            </Card>
          </Space>

          <Card
            title="验收与交付"
            extra={
              <Space wrap>
                <Button
                  loading={acceptanceRun.isPending}
                  onClick={() => acceptanceRun.mutate()}
                >
                  运行验收
                </Button>
                <Button
                  loading={deliveryPackage.isPending}
                  onClick={() => deliveryPackage.mutate()}
                >
                  生成交付包
                </Button>
                <Button
                  loading={compliancePackage.isPending}
                  onClick={() => compliancePackage.mutate()}
                >
                  生成合规包
                </Button>
              </Space>
            }
          >
            <Descriptions column={{ xs: 1, md: 2, xl: 3 }}>
              <Descriptions.Item label="版本">{displayVersion(acceptanceStatus.data.version)}</Descriptions.Item>
              <Descriptions.Item label="运行时已声明">
                <Tag color={acceptanceStatus.data.runtime ? 'green' : 'red'}>
                  {cnBoolean(acceptanceStatus.data.runtime)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="运行时未声明">
                <Tag color={acceptanceStatus.data.runtime_not_claimed ? 'red' : 'green'}>
                  {cnBoolean(acceptanceStatus.data.runtime_not_claimed)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="支持升级路径">
                {acceptanceStatus.data.supported_upgrade_paths.map(displayUpgradePath).join('、')}
              </Descriptions.Item>
              <Descriptions.Item label="失败关键门禁">
                {displayIdentifierList(acceptanceStatus.data.failed_critical_gates)}
              </Descriptions.Item>
              <Descriptions.Item label="已知限制">
                {acceptanceStatus.data.known_limitations.length}
              </Descriptions.Item>
            </Descriptions>
            {acceptanceRun.isError ? (
              <Alert type="error" showIcon message="验收运行失败" description={String(acceptanceRun.error)} />
            ) : null}
            {acceptanceRun.isSuccess ? (
              <Alert
                showIcon
                type="warning"
                message={`验收运行：${cnText(acceptanceRun.data.status)}`}
                description={`Trace ID ${acceptanceRun.data.trace_id}；production_ready=${cnBoolean(
                  acceptanceRun.data.production_ready,
                )}`}
              />
            ) : null}
            {deliveryPackage.isSuccess ? (
              <Alert
                showIcon
                type="success"
                message="交付包已生成"
                description={`${deliveryPackage.data.package_digest}，位置：${deliveryPackage.data.root_path}`}
              />
            ) : null}
            {deliveryPackage.isError ? (
              <Alert type="error" showIcon message="交付包生成失败" description={String(deliveryPackage.error)} />
            ) : null}
            {compliancePackage.isSuccess ? (
              <Alert
                showIcon
                type="success"
                message="合规证据包已生成"
                description={`${compliancePackage.data.controls.length} 个控制项；${compliancePackage.data.disclaimer}`}
              />
            ) : null}
          </Card>

          <Card title="需求可追溯性">
            <List
              dataSource={acceptanceRequirements.data}
              renderItem={(item) => (
                <List.Item>
                  <List.Item.Meta
                    title={
                      <Space wrap>
                        <Typography.Text strong>{displayIdentifier(item.requirement_id)}</Typography.Text>
                        <Tag color={statusColor(item.implementation_status)}>
                          {cnText(item.implementation_status)}
                        </Tag>
                      </Space>
                    }
                    description={
                      <Space direction="vertical">
                        <Typography.Text>{displaySystemText(item.requirement_description)}</Typography.Text>
                        <Typography.Text type="secondary">
                          API：{item.api_operations.length}；迁移：
                          {item.database_migrations.join(', ')}
                        </Typography.Text>
                      </Space>
                    }
                  />
                </List.Item>
              )}
            />
          </Card>

          <Card title="生产就绪门禁">
            <List
              dataSource={productionReadiness.data.critical_gates}
              renderItem={(gate) => (
                <List.Item>
                  <List.Item.Meta
                    title={
                      <Space wrap>
                        <Typography.Text strong>{displayIdentifier(gate.gate_id)}</Typography.Text>
                        <Tag color={statusColor(gate.status)}>{cnText(gate.status)}</Tag>
                        {gate.critical ? <Tag color="red">关键</Tag> : <Tag>非关键</Tag>}
                      </Space>
                    }
                    description={displaySystemText(gate.reason)}
                  />
                </List.Item>
              )}
            />
          </Card>

          <Card
            title="数据治理与密钥生命周期"
            extra={
              <Button loading={dataExport.isPending} onClick={() => dataExport.mutate()}>
                导出租户数据
              </Button>
            }
          >
            {dataExport.isSuccess ? (
              <Alert
                showIcon
                type="success"
                message="租户导出清单已生成"
                description={`已脱敏=${cnBoolean(dataExport.data.redacted)}；密钥数量=${dataExport.data.secret_count}`}
              />
            ) : null}
            {dataExport.isError ? (
              <Alert type="error" showIcon message="数据导出失败" description={String(dataExport.error)} />
            ) : null}
            <Descriptions column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="分类">
                {records(acceptanceStatus.data.data_governance.data_classification).length > 0
                  ? records(acceptanceStatus.data.data_governance.data_classification).length
                  : text(acceptanceStatus.data.data_governance.data_classification)}
              </Descriptions.Item>
              <Descriptions.Item label="租户导出">
                {text(acceptanceStatus.data.data_governance.tenant_exports, '0')}
              </Descriptions.Item>
              <Descriptions.Item label="删除请求">
                {text(acceptanceStatus.data.data_governance.deletion_requests, '0')}
              </Descriptions.Item>
              <Descriptions.Item label="生效法律保留">
                {text(acceptanceStatus.data.data_governance.active_legal_holds, '0')}
              </Descriptions.Item>
              <Descriptions.Item label="密钥显示">
                <Tag color={asRecord(acceptanceStatus.data.secret_lifecycle).redacted_display ? 'green' : 'red'}>
                  已脱敏
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="交付包内密钥">
                {text(asRecord(acceptanceStatus.data.secret_lifecycle).secret_count_in_delivery, '0')}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="合规控制映射">
            <Alert
              showIcon
              type="info"
              message="控制映射不等同于认证。"
              description="平台只导出可供审阅的证据映射，不声明外部认证。"
            />
            <List
              dataSource={complianceControls.data}
              renderItem={(item) => (
                <List.Item>
                  <List.Item.Meta
                    title={
                      <Space wrap>
                        <Typography.Text strong>{item.framework}</Typography.Text>
                        <Tag>{item.control_id}</Tag>
                        <Tag color={item.certification_claim ? 'red' : 'green'}>
                          {item.certification_claim ? '声明认证' : '仅映射'}
                        </Tag>
                      </Space>
                    }
                    description={`${item.implementation} 差距：${item.gap}`}
                  />
                </List.Item>
              )}
            />
          </Card>

          <Card title="运行模式与容量边界">
            <Descriptions column={{ xs: 1, md: 2, xl: 3 }}>
              <Descriptions.Item label="版本">{displayVersion(resilience.version)}</Descriptions.Item>
              <Descriptions.Item label="环境">{cnText(mode.env)}</Descriptions.Item>
              <Descriptions.Item label="数据库">{text(mode.database_mode)}</Descriptions.Item>
              <Descriptions.Item label="队列后端">{text(mode.queue_backend)}</Descriptions.Item>
              <Descriptions.Item label="沙箱后端">{text(mode.sandbox_backend)}</Descriptions.Item>
              <Descriptions.Item label="证据后端">{text(mode.evidence_backend)}</Descriptions.Item>
              <Descriptions.Item label="全局并发">
                {text(capacity.global_concurrency_limit)}
              </Descriptions.Item>
              <Descriptions.Item label="租户并发">
                {text(capacity.tenant_concurrency_limit)}
              </Descriptions.Item>
              <Descriptions.Item label="沙箱容量">
                {text(capacity.sandbox_capacity_limit)}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="服务实例">
            {recordList(resilience.service_instances, 'id', 'last_heartbeat_at')}
          </Card>

          <Card title="验证工作节点">
            {recordList(resilience.workers, 'worker_id', 'last_heartbeat_at')}
          </Card>

          <Card title="队列、NATS 与数据库韧性">
            <Descriptions column={{ xs: 1, md: 2, xl: 3 }}>
              <Descriptions.Item label="就绪">{text(queue.ready, '0')}</Descriptions.Item>
              <Descriptions.Item label="租约中">{text(queue.leased, '0')}</Descriptions.Item>
              <Descriptions.Item label="死信">
                {text(queue.dead_lettered, '0')}
              </Descriptions.Item>
              <Descriptions.Item label="队列深度阈值">
                {text(queue.depth_threshold)}
              </Descriptions.Item>
              <Descriptions.Item label="NATS 流">{text(nats.stream)}</Descriptions.Item>
              <Descriptions.Item label="NATS 消费者">{text(nats.consumer)}</Descriptions.Item>
              <Descriptions.Item label="最大重试次数">
                {text(database.retry_max_attempts)}
              </Descriptions.Item>
              <Descriptions.Item label="重试基础延迟秒数">
                {text(database.retry_base_delay_seconds)}
              </Descriptions.Item>
              <Descriptions.Item label="数据库连接池上限">{text(database.pool_cap)}</Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="公平调度与配额状态">
            <Descriptions column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="全局运行中">{text(fairness.global_running, '0')}</Descriptions.Item>
              <Descriptions.Item label="租户数">{text(fairness.tenants, '0')}</Descriptions.Item>
              <Descriptions.Item label="项目数">{text(fairness.projects, '0')}</Descriptions.Item>
              <Descriptions.Item label="策略">
                优先级不会绕过审批、范围、策略或资源配额。
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card
            title="证据一致性"
            extra={
              <Button
                loading={evidenceCheck.isPending}
                onClick={() => evidenceCheck.mutate()}
              >
                运行检查
              </Button>
            }
          >
            {evidenceCheck.isError ? (
              <Alert
                showIcon
                type="error"
                message="证据一致性检查失败"
                description={String(evidenceCheck.error)}
              />
            ) : null}
            <Descriptions column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="状态">
                <Tag color={statusColor(evidenceConsistency.status)}>
                  {cnText(evidenceConsistency.status, '未检查')}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="报告 ID">{text(evidenceConsistency.id)}</Descriptions.Item>
              <Descriptions.Item label="修复动作">
                {text(evidenceConsistency.repair_action, '无')}
              </Descriptions.Item>
              <Descriptions.Item label="发现项">
                {records(evidenceConsistency.findings).length}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="备份、灾难恢复与混沌保护">
            <Descriptions column={{ xs: 1, md: 2, xl: 3 }}>
              <Descriptions.Item label="备份状态">{cnText(backup.status)}</Descriptions.Item>
              <Descriptions.Item label="最近备份">{text(backup.latest_backup_at)}</Descriptions.Item>
              <Descriptions.Item label="RPO 目标">{text(disasterRecovery.rpo_target)}</Descriptions.Item>
              <Descriptions.Item label="RTO 目标">{text(disasterRecovery.rto_target)}</Descriptions.Item>
              <Descriptions.Item label="最近演练">{text(disasterRecovery.latest_drill_at)}</Descriptions.Item>
              <Descriptions.Item label="混沌已启用">
                <Tag color={chaos.enabled === true ? 'red' : 'green'}>{cnText(chaos.enabled, '否')}</Tag>
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="可用性边界">
            <List
              dataSource={resilience.boundaries}
              renderItem={(item) => <List.Item>{item}</List.Item>}
            />
          </Card>

          {showRaw ? (
            <Card title="原始运行数据">
              <Suspense fallback={<LoadingState label="正在加载 JSON 查看器…" />}>
                <MonacoEditor
                  height="520px"
                  language="json"
                  value={JSON.stringify(
                    {
                      requirements: requirementsQuery.data,
                      resilience,
                      acceptance: acceptanceStatus.data,
                      readiness: productionReadiness.data,
                      requirement_traceability: acceptanceRequirements.data,
                      compliance_controls: complianceControls.data,
                    },
                    null,
                    2,
                  )}
                  options={{ readOnly: true, minimap: { enabled: false }, automaticLayout: true }}
                />
              </Suspense>
            </Card>
          ) : null}
        </Space>
      ) : null}
    </section>
  );
}
