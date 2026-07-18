import { useMutation, useQuery } from '@tanstack/react-query';
import { useParams } from '@tanstack/react-router';
import type {
  DeploymentRecord,
  EnvironmentPromotionCreate,
  ReleaseApprovalCreate,
  ReleaseExceptionCreate,
  ReleaseGateResult,
} from '@vulnlab/shared-types';
import {
  App,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd';

import { queryClient } from '../../../app/query-client';
import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import {
  approveReleaseCandidate,
  detectDeploymentDrift,
  evaluateReleaseCandidate,
  generateCompliancePackage,
  getReleaseCandidate,
  promoteReleaseCandidate,
  requestReleaseException,
  rollbackDeployment,
} from '../../../services/releases';

function statusColor(status: string) {
  if (['passed', 'deployed', 'approved', 'healthy', 'completed'].includes(status)) return 'green';
  if (['failed', 'rejected', 'blocked', 'drift_detected', 'rolled_back'].includes(status)) return 'red';
  if (status === 'warning') return 'gold';
  return 'blue';
}

type ApprovalFormValue = Pick<ReleaseApprovalCreate, 'environment' | 'decision' | 'reason'>;
type ExceptionFormValue = Pick<
  ReleaseExceptionCreate,
  'gate_id' | 'reason' | 'risk' | 'scope' | 'compensating_controls'
>;
type PromotionFormValue = Pick<EnvironmentPromotionCreate, 'environment' | 'canary_percentage'>;

export function ReleaseCandidateDetailPage() {
  const { candidateId } = useParams({ from: '/releases/$candidateId' });
  const { message } = App.useApp();
  const candidate = useQuery({
    queryKey: ['release-candidate', candidateId],
    queryFn: () => getReleaseCandidate(candidateId),
  });
  const invalidate = async () => {
    await queryClient.invalidateQueries({ queryKey: ['release-candidate', candidateId] });
    await queryClient.invalidateQueries({ queryKey: ['release-candidates'] });
  };
  const evaluate = useMutation({
    mutationFn: () => evaluateReleaseCandidate(candidateId, { environment: 'staging' }),
    onSuccess: async () => {
      await invalidate();
      message.success('Staging gates evaluated.');
    },
  });
  const approve = useMutation({
    mutationFn: (value: ReleaseApprovalCreate) => approveReleaseCandidate(candidateId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('Approval recorded.');
    },
  });
  const exception = useMutation({
    mutationFn: (value: ReleaseExceptionCreate) => requestReleaseException(candidateId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('Exception recorded.');
    },
  });
  const promote = useMutation({
    mutationFn: (value: EnvironmentPromotionCreate) => promoteReleaseCandidate(candidateId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('Promotion recorded.');
    },
  });
  const compliance = useMutation({
    mutationFn: () => generateCompliancePackage(candidateId),
    onSuccess: async () => {
      await invalidate();
      message.success('Compliance package generated.');
    },
  });
  const firstDeployment = candidate.data?.deployments?.[0];
  const rollback = useMutation({
    mutationFn: (deployment: DeploymentRecord) =>
      rollbackDeployment(deployment.id, { reason: 'operator requested rollback from console' }),
    onSuccess: async () => {
      await invalidate();
      message.success('Rollback recorded.');
    },
  });
  const drift = useMutation({
    mutationFn: (deployment: DeploymentRecord) => detectDeploymentDrift(deployment.id),
    onSuccess: async () => {
      await invalidate();
      message.success('Drift report recorded.');
    },
  });
  const firstError =
    candidate.error ??
    evaluate.error ??
    approve.error ??
    exception.error ??
    promote.error ??
    rollback.error ??
    drift.error ??
    compliance.error;
  const detail = candidate.data;
  const failedGates = detail?.gates.filter((gate) => gate.status === 'failed') ?? [];

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>Release Candidate</Typography.Title>
        <Typography.Text type="secondary">
          Frozen artifact identity, gate evaluation, approvals, promotion records, drift, rollback, and compliance evidence.
        </Typography.Text>
      </div>
      {candidate.isPending ? <LoadingState /> : null}
      {firstError ? (
        <QueryErrorState
          error={firstError}
          onRetry={() => {
            evaluate.reset();
            approve.reset();
            exception.reset();
            promote.reset();
            rollback.reset();
            drift.reset();
            compliance.reset();
            void candidate.refetch();
          }}
        />
      ) : null}
      {detail ? (
        <>
          <Card title="Frozen release identity">
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="Candidate">{detail.name}</Descriptions.Item>
              <Descriptions.Item label="Status">
                <Tag color={statusColor(detail.status)}>{detail.status}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Project">{detail.project_id}</Descriptions.Item>
              <Descriptions.Item label="Source commit">{detail.source_commit}</Descriptions.Item>
              <Descriptions.Item label="Image digest" span={2}>
                <Typography.Text code>{detail.image_digest}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="SBOM digest">{detail.sbom_digest}</Descriptions.Item>
              <Descriptions.Item label="Provenance digest">{detail.provenance_digest}</Descriptions.Item>
              <Descriptions.Item label="Signature digest">{detail.signature_digest}</Descriptions.Item>
              <Descriptions.Item label="Helm chart digest">{detail.helm_chart_digest}</Descriptions.Item>
              <Descriptions.Item label="Configuration hash">{detail.configuration_hash}</Descriptions.Item>
              <Descriptions.Item label="Freeze hash">{detail.freeze_hash}</Descriptions.Item>
            </Descriptions>
          </Card>

          <Card
            title="Release gates"
            className="section-gap"
            extra={
              <Space>
                <Button loading={evaluate.isPending} onClick={() => evaluate.mutate()}>
                  Evaluate staging
                </Button>
                <Button loading={compliance.isPending} onClick={() => compliance.mutate()}>
                  Compliance package
                </Button>
              </Space>
            }
          >
            <Table<ReleaseGateResult>
              size="small"
              rowKey="id"
              dataSource={detail.gates}
              columns={[
                { title: 'Environment', dataIndex: 'environment' },
                { title: 'Gate', dataIndex: 'gate_id' },
                {
                  title: 'Status',
                  dataIndex: 'status',
                  render: (value: string) => <Tag color={statusColor(value)}>{value}</Tag>,
                },
                { title: 'Reason', dataIndex: 'reason' },
              ]}
            />
          </Card>

          <Card title="Approvals, exceptions, and promotion" className="section-gap">
            <Space direction="vertical" size="large" style={{ width: '100%' }}>
              <Form<ApprovalFormValue>
                layout="inline"
                initialValues={{ environment: 'staging', decision: 'approved' }}
                onFinish={(value) => approve.mutate(value)}
              >
                <Form.Item name="environment" label="Environment" rules={[{ required: true }]}>
                  <Select
                    style={{ width: 150 }}
                    options={['development', 'integration', 'staging', 'production'].map((item) => ({
                      value: item,
                      label: item,
                    }))}
                  />
                </Form.Item>
                <Form.Item name="decision" label="Decision" rules={[{ required: true }]}>
                  <Select
                    style={{ width: 130 }}
                    options={[
                      { value: 'approved', label: 'approved' },
                      { value: 'rejected', label: 'rejected' },
                    ]}
                  />
                </Form.Item>
                <Form.Item name="reason" label="Reason">
                  <Input placeholder="approval reason" />
                </Form.Item>
                <Button htmlType="submit" loading={approve.isPending}>Record approval</Button>
              </Form>

              <Form<PromotionFormValue>
                layout="inline"
                initialValues={{ environment: 'staging', canary_percentage: 25 }}
                onFinish={(value) =>
                  promote.mutate({
                    environment: value.environment,
                    canary_percentage: value.canary_percentage,
                    health: { rollout_gate: 'manual-console-record' },
                  })
                }
              >
                <Form.Item name="environment" label="Promotion" rules={[{ required: true }]}>
                  <Select
                    style={{ width: 150 }}
                    options={['development', 'integration', 'staging', 'production'].map((item) => ({
                      value: item,
                      label: item,
                    }))}
                  />
                </Form.Item>
                <Form.Item name="canary_percentage" label="Canary">
                  <InputNumber min={0} max={100} />
                </Form.Item>
                <Button htmlType="submit" loading={promote.isPending}>Promote</Button>
              </Form>

              <Form<ExceptionFormValue>
                layout="inline"
                initialValues={{
                  gate_id: failedGates[0]?.gate_id ?? 'p12_authoritative_runtime',
                  risk: 'medium',
                  scope: 'staging-only',
                  compensating_controls: ['manual-review'],
                }}
                onFinish={(value) =>
                  exception.mutate({
                    ...value,
                    approve: value.risk !== 'critical',
                    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
                  })
                }
              >
                <Form.Item name="gate_id" label="Exception gate" rules={[{ required: true }]}>
                  <Input style={{ width: 220 }} />
                </Form.Item>
                <Form.Item name="risk" label="Risk" rules={[{ required: true }]}>
                  <Select
                    style={{ width: 120 }}
                    options={['low', 'medium', 'high', 'critical'].map((item) => ({ value: item, label: item }))}
                  />
                </Form.Item>
                <Form.Item name="scope" label="Scope" rules={[{ required: true }]}>
                  <Input style={{ width: 160 }} />
                </Form.Item>
                <Form.Item name="reason" label="Reason" rules={[{ required: true }]}>
                  <Input placeholder="exception reason" />
                </Form.Item>
                <Button htmlType="submit" loading={exception.isPending}>Request exception</Button>
              </Form>
            </Space>
          </Card>

          <Card title="Supply-chain evidence" className="section-gap">
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="SBOM documents">{detail.artifact.sbom_documents.length}</Descriptions.Item>
              <Descriptions.Item label="Provenance statements">{detail.artifact.provenance_statements.length}</Descriptions.Item>
              <Descriptions.Item label="Signature records">{detail.artifact.signature_records.length}</Descriptions.Item>
              <Descriptions.Item label="Security scans">{detail.artifact.security_scans.length}</Descriptions.Item>
              <Descriptions.Item label="License scans">{detail.artifact.license_scans.length}</Descriptions.Item>
              <Descriptions.Item label="Artifact repository">{detail.artifact.repository}</Descriptions.Item>
            </Descriptions>
          </Card>

          <Card
            title="Deployments and drift"
            className="section-gap"
            extra={
              firstDeployment ? (
                <Space>
                  <Button loading={drift.isPending} onClick={() => drift.mutate(firstDeployment)}>
                    Detect drift
                  </Button>
                  <Button danger loading={rollback.isPending} onClick={() => rollback.mutate(firstDeployment)}>
                    Rollback latest
                  </Button>
                </Space>
              ) : null
            }
          >
            <Table
              size="small"
              rowKey="id"
              dataSource={detail.deployments}
              columns={[
                { title: 'Environment', dataIndex: 'environment' },
                {
                  title: 'Status',
                  dataIndex: 'status',
                  render: (value: string) => <Tag color={statusColor(value)}>{value}</Tag>,
                },
                { title: 'Canary', dataIndex: 'canary_percentage', render: (value: number) => `${value}%` },
                {
                  title: 'Digest',
                  dataIndex: 'image_digest',
                  render: (value: string) => <Typography.Text code>{value.slice(0, 48)}...</Typography.Text>,
                },
                { title: 'Updated', dataIndex: 'updated_at' },
              ]}
            />
          </Card>
        </>
      ) : null}
    </section>
  );
}
