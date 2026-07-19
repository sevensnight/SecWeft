import { useMutation, useQuery } from '@tanstack/react-query';
import { Alert, Button, Card, Descriptions, List, Space, Statistic, Tag, Typography } from 'antd';
import { lazy, Suspense, useState } from 'react';
import type { SystemResilience } from '@vulnlab/shared-types';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
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
  version: 'not reported',
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

function text(value: unknown, fallback = 'not reported'): string {
  if (typeof value === 'string' && value.length > 0) return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
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

function recordList(recordsValue: JsonRecord[], primary: string, secondary: string) {
  if (recordsValue.length === 0) {
    return <Typography.Text type="secondary">No records reported.</Typography.Text>;
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
                <Tag color={statusColor(item.status)}>{text(item.status, 'unknown')}</Tag>
              </Space>
            }
            description={
              <Typography.Text type="secondary">
                {secondary}: {text(item[secondary])}
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
          <Typography.Title level={2}>System operations</Typography.Title>
          <Typography.Text type="secondary">
            P12 high availability, capacity, evidence consistency, backup, and disaster recovery.
          </Typography.Text>
        </div>
        <Button onClick={() => setShowRaw((current) => !current)}>
          {showRaw ? 'Hide raw JSON' : 'Show raw JSON'}
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
        <Space direction="vertical" size="large" className="full-width">
          <Alert
            showIcon
            type={requirementsQuery.data.p0_migration.legacy_execution_enabled ? 'warning' : 'success'}
            message={`Compatibility mode: ${requirementsQuery.data.p0_migration.status}`}
            description={requirementsQuery.data.p0_migration.compatibility}
          />
          <Alert
            showIcon
            type={productionReadiness.data.production_ready ? 'success' : 'error'}
            message={`Production readiness: ${
              productionReadiness.data.production_ready ? 'ready' : 'blocked'
            }`}
            description={
              productionReadiness.data.runtime_not_claimed
                ? 'Authoritative GitHub isolated runtime evidence is missing; production_ready remains false.'
                : 'All critical gates have runtime evidence.'
            }
          />

          <Space wrap size="large">
            <Card>
              <Statistic title="Control-plane instances" value={resilience.service_instances.length} />
            </Card>
            <Card>
              <Statistic title="Workers" value={resilience.workers.length} />
            </Card>
            <Card>
              <Statistic title="Pending queue" value={numberValue(queue.pending)} />
            </Card>
            <Card>
              <Statistic
                title="Evidence status"
                value={text(evidenceConsistency.status, 'not checked')}
                valueStyle={{ color: statusColor(evidenceConsistency.status) }}
              />
            </Card>
            <Card>
              <Statistic
                title="Production ready"
                value={productionReadiness.data.production_ready ? 'yes' : 'no'}
                valueStyle={{
                  color: productionReadiness.data.production_ready ? 'green' : 'red',
                }}
              />
            </Card>
            <Card>
              <Statistic
                title="Traceability items"
                value={acceptanceRequirements.data.length}
              />
            </Card>
          </Space>

          <Card
            title="P14 enterprise acceptance and delivery"
            extra={
              <Space wrap>
                <Button
                  loading={acceptanceRun.isPending}
                  onClick={() => acceptanceRun.mutate()}
                >
                  Run acceptance
                </Button>
                <Button
                  loading={deliveryPackage.isPending}
                  onClick={() => deliveryPackage.mutate()}
                >
                  Generate delivery package
                </Button>
                <Button
                  loading={compliancePackage.isPending}
                  onClick={() => compliancePackage.mutate()}
                >
                  Generate compliance package
                </Button>
              </Space>
            }
          >
            <Descriptions column={{ xs: 1, md: 2, xl: 3 }}>
              <Descriptions.Item label="Version">{acceptanceStatus.data.version}</Descriptions.Item>
              <Descriptions.Item label="Runtime claimed">
                <Tag color={acceptanceStatus.data.runtime ? 'green' : 'red'}>
                  {String(acceptanceStatus.data.runtime)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Runtime not claimed">
                <Tag color={acceptanceStatus.data.runtime_not_claimed ? 'red' : 'green'}>
                  {String(acceptanceStatus.data.runtime_not_claimed)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Supported upgrades">
                {acceptanceStatus.data.supported_upgrade_paths.join(', ')}
              </Descriptions.Item>
              <Descriptions.Item label="Failed critical gates">
                {acceptanceStatus.data.failed_critical_gates.join(', ') || 'none'}
              </Descriptions.Item>
              <Descriptions.Item label="Known limitations">
                {acceptanceStatus.data.known_limitations.length}
              </Descriptions.Item>
            </Descriptions>
            {acceptanceRun.isError ? (
              <Alert type="error" showIcon message="Acceptance run failed" description={String(acceptanceRun.error)} />
            ) : null}
            {acceptanceRun.isSuccess ? (
              <Alert
                showIcon
                type="warning"
                message={`Acceptance run: ${acceptanceRun.data.status}`}
                description={`Trace ID ${acceptanceRun.data.trace_id}; production_ready=${acceptanceRun.data.production_ready}`}
              />
            ) : null}
            {deliveryPackage.isSuccess ? (
              <Alert
                showIcon
                type="success"
                message="Delivery package generated"
                description={`${deliveryPackage.data.package_digest} at ${deliveryPackage.data.root_path}`}
              />
            ) : null}
            {deliveryPackage.isError ? (
              <Alert type="error" showIcon message="Delivery package failed" description={String(deliveryPackage.error)} />
            ) : null}
            {compliancePackage.isSuccess ? (
              <Alert
                showIcon
                type="success"
                message="Compliance evidence package generated"
                description={`${compliancePackage.data.controls.length} controls; ${compliancePackage.data.disclaimer}`}
              />
            ) : null}
          </Card>

          <Card title="Requirement traceability">
            <List
              dataSource={acceptanceRequirements.data}
              renderItem={(item) => (
                <List.Item>
                  <List.Item.Meta
                    title={
                      <Space wrap>
                        <Typography.Text strong>{item.requirement_id}</Typography.Text>
                        <Tag color={statusColor(item.implementation_status)}>
                          {item.implementation_status}
                        </Tag>
                      </Space>
                    }
                    description={
                      <Space direction="vertical">
                        <Typography.Text>{item.requirement_description}</Typography.Text>
                        <Typography.Text type="secondary">
                          APIs: {item.api_operations.length}; migrations:{' '}
                          {item.database_migrations.join(', ')}
                        </Typography.Text>
                      </Space>
                    }
                  />
                </List.Item>
              )}
            />
          </Card>

          <Card title="Production readiness gates">
            <List
              dataSource={productionReadiness.data.critical_gates}
              renderItem={(gate) => (
                <List.Item>
                  <List.Item.Meta
                    title={
                      <Space wrap>
                        <Typography.Text strong>{gate.gate_id}</Typography.Text>
                        <Tag color={statusColor(gate.status)}>{gate.status}</Tag>
                        {gate.critical ? <Tag color="red">critical</Tag> : <Tag>non-critical</Tag>}
                      </Space>
                    }
                    description={gate.reason}
                  />
                </List.Item>
              )}
            />
          </Card>

          <Card
            title="Data governance and secret lifecycle"
            extra={
              <Button loading={dataExport.isPending} onClick={() => dataExport.mutate()}>
                Export tenant data
              </Button>
            }
          >
            {dataExport.isSuccess ? (
              <Alert
                showIcon
                type="success"
                message="Tenant export manifest generated"
                description={`redacted=${dataExport.data.redacted}; secret_count=${dataExport.data.secret_count}`}
              />
            ) : null}
            {dataExport.isError ? (
              <Alert type="error" showIcon message="Data export failed" description={String(dataExport.error)} />
            ) : null}
            <Descriptions column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="Classifications">
                {records(acceptanceStatus.data.data_governance.data_classification).length > 0
                  ? records(acceptanceStatus.data.data_governance.data_classification).length
                  : text(acceptanceStatus.data.data_governance.data_classification)}
              </Descriptions.Item>
              <Descriptions.Item label="Tenant exports">
                {text(acceptanceStatus.data.data_governance.tenant_exports, '0')}
              </Descriptions.Item>
              <Descriptions.Item label="Deletion requests">
                {text(acceptanceStatus.data.data_governance.deletion_requests, '0')}
              </Descriptions.Item>
              <Descriptions.Item label="Active legal holds">
                {text(acceptanceStatus.data.data_governance.active_legal_holds, '0')}
              </Descriptions.Item>
              <Descriptions.Item label="Secret display">
                <Tag color={asRecord(acceptanceStatus.data.secret_lifecycle).redacted_display ? 'green' : 'red'}>
                  redacted
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Secrets in delivery">
                {text(asRecord(acceptanceStatus.data.secret_lifecycle).secret_count_in_delivery, '0')}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="Compliance control mapping">
            <Alert
              showIcon
              type="info"
              message="Control mapping is not certification."
              description="The platform exports evidence mappings for review; it does not claim external certification."
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
                          {item.certification_claim ? 'certification claimed' : 'mapping only'}
                        </Tag>
                      </Space>
                    }
                    description={`${item.implementation} Gap: ${item.gap}`}
                  />
                </List.Item>
              )}
            />
          </Card>

          <Card title="Runtime mode and capacity boundaries">
            <Descriptions column={{ xs: 1, md: 2, xl: 3 }}>
              <Descriptions.Item label="Version">{resilience.version}</Descriptions.Item>
              <Descriptions.Item label="Environment">{text(mode.env)}</Descriptions.Item>
              <Descriptions.Item label="Database">{text(mode.database_mode)}</Descriptions.Item>
              <Descriptions.Item label="Queue backend">{text(mode.queue_backend)}</Descriptions.Item>
              <Descriptions.Item label="Sandbox backend">{text(mode.sandbox_backend)}</Descriptions.Item>
              <Descriptions.Item label="Evidence backend">{text(mode.evidence_backend)}</Descriptions.Item>
              <Descriptions.Item label="Global concurrency">
                {text(capacity.global_concurrency_limit)}
              </Descriptions.Item>
              <Descriptions.Item label="Tenant concurrency">
                {text(capacity.tenant_concurrency_limit)}
              </Descriptions.Item>
              <Descriptions.Item label="Sandbox capacity">
                {text(capacity.sandbox_capacity_limit)}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="Service instances">
            {recordList(resilience.service_instances, 'id', 'last_heartbeat_at')}
          </Card>

          <Card title="Validation workers">
            {recordList(resilience.workers, 'worker_id', 'last_heartbeat_at')}
          </Card>

          <Card title="Queue, NATS, and database resilience">
            <Descriptions column={{ xs: 1, md: 2, xl: 3 }}>
              <Descriptions.Item label="Ready">{text(queue.ready, '0')}</Descriptions.Item>
              <Descriptions.Item label="Leased">{text(queue.leased, '0')}</Descriptions.Item>
              <Descriptions.Item label="Dead-lettered">
                {text(queue.dead_lettered, '0')}
              </Descriptions.Item>
              <Descriptions.Item label="Queue depth threshold">
                {text(queue.depth_threshold)}
              </Descriptions.Item>
              <Descriptions.Item label="NATS stream">{text(nats.stream)}</Descriptions.Item>
              <Descriptions.Item label="NATS consumer">{text(nats.consumer)}</Descriptions.Item>
              <Descriptions.Item label="Retry max attempts">
                {text(database.retry_max_attempts)}
              </Descriptions.Item>
              <Descriptions.Item label="Retry base delay seconds">
                {text(database.retry_base_delay_seconds)}
              </Descriptions.Item>
              <Descriptions.Item label="Database pool cap">{text(database.pool_cap)}</Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="Fairness and quota posture">
            <Descriptions column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="Global running">{text(fairness.global_running, '0')}</Descriptions.Item>
              <Descriptions.Item label="Tenants">{text(fairness.tenants, '0')}</Descriptions.Item>
              <Descriptions.Item label="Projects">{text(fairness.projects, '0')}</Descriptions.Item>
              <Descriptions.Item label="Policy">
                Priority never bypasses approval, scope, policy, or resource quota.
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card
            title="Evidence consistency"
            extra={
              <Button
                loading={evidenceCheck.isPending}
                onClick={() => evidenceCheck.mutate()}
              >
                Run check
              </Button>
            }
          >
            {evidenceCheck.isError ? (
              <Alert
                showIcon
                type="error"
                message="Evidence consistency check failed"
                description={String(evidenceCheck.error)}
              />
            ) : null}
            <Descriptions column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="Status">
                <Tag color={statusColor(evidenceConsistency.status)}>
                  {text(evidenceConsistency.status, 'not checked')}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Report ID">{text(evidenceConsistency.id)}</Descriptions.Item>
              <Descriptions.Item label="Repair action">
                {text(evidenceConsistency.repair_action, 'none')}
              </Descriptions.Item>
              <Descriptions.Item label="Findings">
                {records(evidenceConsistency.findings).length}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="Backup, disaster recovery, and chaos guard">
            <Descriptions column={{ xs: 1, md: 2, xl: 3 }}>
              <Descriptions.Item label="Backup status">{text(backup.status)}</Descriptions.Item>
              <Descriptions.Item label="Last backup">{text(backup.latest_backup_at)}</Descriptions.Item>
              <Descriptions.Item label="RPO target">{text(disasterRecovery.rpo_target)}</Descriptions.Item>
              <Descriptions.Item label="RTO target">{text(disasterRecovery.rto_target)}</Descriptions.Item>
              <Descriptions.Item label="Last drill">{text(disasterRecovery.latest_drill_at)}</Descriptions.Item>
              <Descriptions.Item label="Chaos enabled">
                <Tag color={chaos.enabled === true ? 'red' : 'green'}>{text(chaos.enabled, 'false')}</Tag>
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="Availability boundaries">
            <List
              dataSource={resilience.boundaries}
              renderItem={(item) => <List.Item>{item}</List.Item>}
            />
          </Card>

          {showRaw ? (
            <Card title="Raw operational payload">
              <Suspense fallback={<LoadingState label="Loading JSON viewer" />}>
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
