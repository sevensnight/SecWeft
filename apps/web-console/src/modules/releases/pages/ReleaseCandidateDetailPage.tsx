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
import { cnLabel } from '../../../i18n/formatters';
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
      message.success('预发布门禁已评估。');
    },
  });
  const approve = useMutation({
    mutationFn: (value: ReleaseApprovalCreate) => approveReleaseCandidate(candidateId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('审批已记录。');
    },
  });
  const exception = useMutation({
    mutationFn: (value: ReleaseExceptionCreate) => requestReleaseException(candidateId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('例外已记录。');
    },
  });
  const promote = useMutation({
    mutationFn: (value: EnvironmentPromotionCreate) => promoteReleaseCandidate(candidateId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('环境提升已记录。');
    },
  });
  const compliance = useMutation({
    mutationFn: () => generateCompliancePackage(candidateId),
    onSuccess: async () => {
      await invalidate();
      message.success('合规包已生成。');
    },
  });
  const firstDeployment = candidate.data?.deployments?.[0];
  const rollback = useMutation({
    mutationFn: (deployment: DeploymentRecord) =>
      rollbackDeployment(deployment.id, { reason: '控制台操作者请求回滚' }),
    onSuccess: async () => {
      await invalidate();
      message.success('回滚已记录。');
    },
  });
  const drift = useMutation({
    mutationFn: (deployment: DeploymentRecord) => detectDeploymentDrift(deployment.id),
    onSuccess: async () => {
      await invalidate();
      message.success('漂移报告已记录。');
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
        <Typography.Title level={2}>发布候选详情</Typography.Title>
        <Typography.Text type="secondary">
          展示冻结产物身份、门禁评估、审批、环境提升、漂移、回滚和合规证据。
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
          <Card title="冻结发布身份">
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="候选">{detail.name}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={statusColor(detail.status)}>{cnLabel(detail.status)}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="项目">{detail.project_id}</Descriptions.Item>
              <Descriptions.Item label="源码提交">{detail.source_commit}</Descriptions.Item>
              <Descriptions.Item label="镜像摘要" span={2}>
                <Typography.Text code>{detail.image_digest}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="SBOM 摘要">{detail.sbom_digest}</Descriptions.Item>
              <Descriptions.Item label="来源证明摘要">{detail.provenance_digest}</Descriptions.Item>
              <Descriptions.Item label="签名摘要">{detail.signature_digest}</Descriptions.Item>
              <Descriptions.Item label="Helm 图表摘要">{detail.helm_chart_digest}</Descriptions.Item>
              <Descriptions.Item label="配置哈希">{detail.configuration_hash}</Descriptions.Item>
              <Descriptions.Item label="冻结哈希">{detail.freeze_hash}</Descriptions.Item>
            </Descriptions>
          </Card>

          <Card
            title="发布门禁"
            className="section-gap"
            extra={
              <Space>
                <Button loading={evaluate.isPending} onClick={() => evaluate.mutate()}>
                  评估预发布
                </Button>
                <Button loading={compliance.isPending} onClick={() => compliance.mutate()}>
                  生成合规包
                </Button>
              </Space>
            }
          >
            <Table<ReleaseGateResult>
              size="small"
              rowKey="id"
              dataSource={detail.gates}
              columns={[
                { title: '环境', dataIndex: 'environment', render: (value: string) => cnLabel(value) },
                { title: '门禁', dataIndex: 'gate_id' },
                {
                  title: '状态',
                  dataIndex: 'status',
                  render: (value: string) => <Tag color={statusColor(value)}>{cnLabel(value)}</Tag>,
                },
                { title: '原因', dataIndex: 'reason' },
              ]}
            />
          </Card>

          <Card title="审批、例外与环境提升" className="section-gap">
            <Space direction="vertical" size="large" style={{ width: '100%' }}>
              <Form<ApprovalFormValue>
                layout="inline"
                initialValues={{ environment: 'staging', decision: 'approved' }}
                onFinish={(value) => approve.mutate(value)}
              >
                <Form.Item name="environment" label="环境" rules={[{ required: true }]}>
                  <Select
                    style={{ width: 150 }}
                    options={['development', 'integration', 'staging', 'production'].map((item) => ({
                      value: item,
                      label: cnLabel(item),
                    }))}
                  />
                </Form.Item>
                <Form.Item name="decision" label="决策" rules={[{ required: true }]}>
                  <Select
                    style={{ width: 130 }}
                    options={[
                      { value: 'approved', label: '已批准' },
                      { value: 'rejected', label: '已拒绝' },
                    ]}
                  />
                </Form.Item>
                <Form.Item name="reason" label="原因">
                  <Input placeholder="填写审批原因" />
                </Form.Item>
                <Button htmlType="submit" loading={approve.isPending}>记录审批</Button>
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
                <Form.Item name="environment" label="提升环境" rules={[{ required: true }]}>
                  <Select
                    style={{ width: 150 }}
                    options={['development', 'integration', 'staging', 'production'].map((item) => ({
                      value: item,
                      label: cnLabel(item),
                    }))}
                  />
                </Form.Item>
                <Form.Item name="canary_percentage" label="金丝雀比例">
                  <InputNumber min={0} max={100} />
                </Form.Item>
                <Button htmlType="submit" loading={promote.isPending}>提升</Button>
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
                <Form.Item name="gate_id" label="例外门禁" rules={[{ required: true }]}>
                  <Input style={{ width: 220 }} />
                </Form.Item>
                <Form.Item name="risk" label="风险" rules={[{ required: true }]}>
                  <Select
                    style={{ width: 120 }}
                    options={['low', 'medium', 'high', 'critical'].map((item) => ({
                      value: item,
                      label: cnLabel(item),
                    }))}
                  />
                </Form.Item>
                <Form.Item name="scope" label="范围" rules={[{ required: true }]}>
                  <Input style={{ width: 160 }} />
                </Form.Item>
                <Form.Item name="reason" label="原因" rules={[{ required: true }]}>
                  <Input placeholder="填写例外原因" />
                </Form.Item>
                <Button htmlType="submit" loading={exception.isPending}>申请例外</Button>
              </Form>
            </Space>
          </Card>

          <Card title="供应链证据" className="section-gap">
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="SBOM 文档">{detail.artifact.sbom_documents.length}</Descriptions.Item>
              <Descriptions.Item label="来源证明">{detail.artifact.provenance_statements.length}</Descriptions.Item>
              <Descriptions.Item label="签名记录">{detail.artifact.signature_records.length}</Descriptions.Item>
              <Descriptions.Item label="安全扫描">{detail.artifact.security_scans.length}</Descriptions.Item>
              <Descriptions.Item label="许可证扫描">{detail.artifact.license_scans.length}</Descriptions.Item>
              <Descriptions.Item label="产物仓库">{detail.artifact.repository}</Descriptions.Item>
            </Descriptions>
          </Card>

          <Card
            title="部署与漂移"
            className="section-gap"
            extra={
              firstDeployment ? (
                <Space>
                  <Button loading={drift.isPending} onClick={() => drift.mutate(firstDeployment)}>
                    检测漂移
                  </Button>
                  <Button danger loading={rollback.isPending} onClick={() => rollback.mutate(firstDeployment)}>
                    回滚最新部署
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
                { title: '环境', dataIndex: 'environment', render: (value: string) => cnLabel(value) },
                {
                  title: '状态',
                  dataIndex: 'status',
                  render: (value: string) => <Tag color={statusColor(value)}>{cnLabel(value)}</Tag>,
                },
                { title: '金丝雀比例', dataIndex: 'canary_percentage', render: (value: number) => `${value}%` },
                {
                  title: '摘要',
                  dataIndex: 'image_digest',
                  render: (value: string) => <Typography.Text code>{value.slice(0, 48)}...</Typography.Text>,
                },
                { title: '更新时间', dataIndex: 'updated_at' },
              ]}
            />
          </Card>
        </>
      ) : null}
    </section>
  );
}
