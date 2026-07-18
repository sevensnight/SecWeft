import { useMutation, useQuery } from '@tanstack/react-query';
import { useParams } from '@tanstack/react-router';
import type {
  EvaluationComparison,
  EvaluationFailure,
  EvaluationReviewCreate,
  EvaluationRunVariant,
  MetricResult,
  PromotionDecisionCreate,
} from '@vulnlab/shared-types';
import {
  App,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
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
  createEvaluationReview,
  createPromotionDecision,
  getEvaluationRun,
  listEvaluationFailures,
  listEvaluationMetrics,
} from '../../../services/evaluations';

function statusColor(status: string) {
  if (['PASSED', 'APPROVED', 'PROMOTED', 'ACCEPTED'].includes(status)) return 'green';
  if (['FAILED', 'REJECTED', 'ROLLED_BACK'].includes(status)) return 'red';
  if (status === 'CANCELLED') return 'default';
  return 'blue';
}

function metricValue(value: number) {
  if (Number.isInteger(value)) return value.toString();
  return value.toFixed(value < 1 ? 4 : 2);
}

export function EvaluationRunDetailPage() {
  const { runId } = useParams({ from: '/evaluations/$runId' });
  const { message } = App.useApp();
  const run = useQuery({
    queryKey: ['evaluation-run', runId],
    queryFn: () => getEvaluationRun(runId),
  });
  const metrics = useQuery({
    queryKey: ['evaluation-run-metrics', runId],
    queryFn: () => listEvaluationMetrics(runId),
  });
  const failures = useQuery({
    queryKey: ['evaluation-run-failures', runId],
    queryFn: () => listEvaluationFailures(runId),
  });
  const review = useMutation({
    mutationFn: (value: EvaluationReviewCreate) => createEvaluationReview(runId, value),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['evaluation-run', runId] });
      message.success('Review recorded.');
    },
  });
  const promotion = useMutation({
    mutationFn: (value: PromotionDecisionCreate) => createPromotionDecision(runId, value),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['evaluation-run', runId] });
      message.success('Promotion decision recorded.');
    },
  });
  const firstError = run.error ?? metrics.error ?? failures.error ?? review.error ?? promotion.error;
  const detail = run.data;
  const latestComparison = detail?.comparisons?.[0];
  const securityMetrics = (metrics.data ?? []).filter(
    (metric) => metric.category === 'security' && metric.value > 0,
  );
  const costLatency = (metrics.data ?? []).filter((metric) =>
    ['average_cost', 'total_cost', 'p95_latency', 'end_to_end_latency', 'input_tokens', 'output_tokens'].includes(metric.metric_name),
  );

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>Evaluation Run</Typography.Title>
        <Typography.Text type="secondary">
          Immutable configuration hash, variant matrix, metrics, regression comparison, review, and promotion gate.
        </Typography.Text>
      </div>
      {run.isPending ? <LoadingState /> : null}
      {firstError ? (
        <QueryErrorState
          error={firstError}
          onRetry={() => {
            review.reset();
            promotion.reset();
            void run.refetch();
            void metrics.refetch();
            void failures.refetch();
          }}
        />
      ) : null}
      {detail ? (
        <>
          <Card title="Run status">
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="Run">{detail.id}</Descriptions.Item>
              <Descriptions.Item label="Type">{detail.evaluation_type}</Descriptions.Item>
              <Descriptions.Item label="Status">
                <Tag color={statusColor(detail.status)}>{detail.status}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Gate">
                <Tag color={statusColor(detail.gate_status)}>{detail.gate_status}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Project">{detail.project_id}</Descriptions.Item>
              <Descriptions.Item label="Version">{detail.version_no}</Descriptions.Item>
              <Descriptions.Item label="Config hash" span={2}>{detail.config_hash}</Descriptions.Item>
              <Descriptions.Item label="Started">{detail.started_at ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="Finished">{detail.finished_at ?? '-'}</Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="Variant configuration matrix" className="section-gap">
            <Table<EvaluationRunVariant>
              size="small"
              rowKey="id"
              dataSource={detail.variants}
              columns={[
                { title: 'Role', dataIndex: 'role', render: (value: string) => <Tag>{value}</Tag> },
                { title: 'Name', dataIndex: 'name' },
                { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{value}</Tag> },
                { title: 'Snapshot', dataIndex: 'configuration_snapshot_id', render: (value: string) => value.slice(0, 8) },
                { title: 'Config hash', dataIndex: 'configuration_hash', render: (value: string) => value.slice(0, 16) },
              ]}
            />
          </Card>

          <Card title="Metric scorecard" className="section-gap" loading={metrics.isPending}>
            <Table<MetricResult>
              size="small"
              rowKey="id"
              dataSource={metrics.data ?? []}
              columns={[
                { title: 'Variant', dataIndex: 'variant_id', render: (value: string) => value.slice(0, 8) },
                { title: 'Metric', dataIndex: 'metric_name' },
                { title: 'Category', dataIndex: 'category', render: (value: string) => <Tag>{value}</Tag> },
                { title: 'Value', dataIndex: 'value', render: (value: number) => metricValue(value) },
                { title: 'Unit', dataIndex: 'unit' },
              ]}
            />
          </Card>

          <Card title="Baseline comparison and gate" className="section-gap">
            {latestComparison ? (
              <Descriptions bordered size="small" column={2}>
                <Descriptions.Item label="Gate">
                  <Tag color={statusColor(latestComparison.gate_status)}>{latestComparison.gate_status}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label="Security gate">
                  <Tag color={statusColor(latestComparison.security_gate_status)}>
                    {latestComparison.security_gate_status}
                  </Tag>
                </Descriptions.Item>
                <Descriptions.Item label="Improved" span={2}>
                  <Space wrap>{latestComparison.improved_metrics.map((item) => <Tag color="green" key={item}>{item}</Tag>)}</Space>
                </Descriptions.Item>
                <Descriptions.Item label="Regressed" span={2}>
                  <Space wrap>{latestComparison.regressed_metrics.map((item) => <Tag color="red" key={item}>{item}</Tag>)}</Space>
                </Descriptions.Item>
                <Descriptions.Item label="Failed gates" span={2}>
                  <Space wrap>{latestComparison.failed_gates.map((item) => <Tag color="red" key={item}>{item}</Tag>)}</Space>
                </Descriptions.Item>
                <Descriptions.Item label="Cost change">{latestComparison.cost_change}</Descriptions.Item>
                <Descriptions.Item label="Latency change">{latestComparison.latency_change}</Descriptions.Item>
              </Descriptions>
            ) : (
              <Typography.Text type="secondary">No comparison yet.</Typography.Text>
            )}
          </Card>

          <Card title="Failures and security violations" className="section-gap" loading={failures.isPending}>
            <Typography.Title level={5}>Failed cases</Typography.Title>
            <Table<EvaluationFailure>
              size="small"
              rowKey="result_id"
              dataSource={failures.data ?? []}
              columns={[
                { title: 'Variant', dataIndex: 'variant_id', render: (value: string) => value.slice(0, 8) },
                { title: 'Case', dataIndex: 'external_id' },
                { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{value}</Tag> },
                { title: 'Reasons', dataIndex: 'failure_reasons', render: (value: string[]) => value.join(', ') },
              ]}
            />
            <Typography.Title level={5}>Security violations</Typography.Title>
            <Table<MetricResult>
              size="small"
              rowKey="id"
              dataSource={securityMetrics}
              columns={[
                { title: 'Metric', dataIndex: 'metric_name' },
                { title: 'Value', dataIndex: 'value', render: (value: number) => metricValue(value) },
                { title: 'Variant', dataIndex: 'variant_id', render: (value: string) => value.slice(0, 8) },
              ]}
            />
            <Typography.Title level={5}>Cost and latency</Typography.Title>
            <Table<MetricResult>
              size="small"
              rowKey="id"
              dataSource={costLatency}
              columns={[
                { title: 'Metric', dataIndex: 'metric_name' },
                { title: 'Value', dataIndex: 'value', render: (value: number) => metricValue(value) },
                { title: 'Variant', dataIndex: 'variant_id', render: (value: string) => value.slice(0, 8) },
              ]}
            />
          </Card>

          <Card title="Human review and promotion" className="section-gap">
            <Space align="start" wrap>
              <Form
                layout="vertical"
                initialValues={{ decision: 'ACCEPTED', blind: true }}
                onFinish={(value) => review.mutate({
                  decision: value.decision,
                  blind: value.blind ?? true,
                  comments: value.comments,
                  annotations: {},
                })}
              >
                <Form.Item name="decision" label="Review decision" rules={[{ required: true }]}>
                  <Select
                    className="compact-select"
                    options={['ACCEPTED', 'REJECTED', 'CHANGES_REQUESTED'].map((value) => ({ value, label: value }))}
                  />
                </Form.Item>
                <Form.Item name="comments" label="Comments" rules={[{ required: true }]}>
                  <Input className="wide-input" />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={review.isPending}>Record review</Button>
              </Form>
              <Form
                layout="vertical"
                initialValues={{ decision: 'APPROVED', target_environment: 'production' }}
                onFinish={(value) => promotion.mutate({
                  decision: value.decision,
                  reason: value.reason,
                  expected_version: detail.version_no,
                  target_environment: value.target_environment,
                })}
              >
                <Form.Item name="decision" label="Promotion decision" rules={[{ required: true }]}>
                  <Select
                    className="compact-select"
                    options={['APPROVED', 'REJECTED', 'PROMOTED', 'ROLLED_BACK'].map((value) => ({ value, label: value }))}
                  />
                </Form.Item>
                <Form.Item name="reason" label="Reason" rules={[{ required: true }]}>
                  <Input className="wide-input" />
                </Form.Item>
                <Form.Item name="target_environment" label="Target">
                  <Input />
                </Form.Item>
                <Button htmlType="submit" loading={promotion.isPending}>Record decision</Button>
              </Form>
            </Space>
          </Card>
        </>
      ) : null}
    </section>
  );
}
