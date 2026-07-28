import { useMutation, useQuery } from '@tanstack/react-query';
import { useParams } from '@tanstack/react-router';
import type {
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
import { cnLabel } from '../../../i18n/formatters';
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

type EvaluationReviewFormValue = Pick<
  EvaluationReviewCreate,
  'decision' | 'blind' | 'comments'
>;

type PromotionDecisionFormValue = Pick<
  PromotionDecisionCreate,
  'decision' | 'reason' | 'target_environment'
>;

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
      message.success('复核已记录。');
    },
  });
  const promotion = useMutation({
    mutationFn: (value: PromotionDecisionCreate) => createPromotionDecision(runId, value),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['evaluation-run', runId] });
      message.success('提升决策已记录。');
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
        <Typography.Title level={2}>评测运行</Typography.Title>
        <Typography.Text type="secondary">
          查看不可变配置哈希、变体矩阵、指标、回归对比、人工复核和提升门禁。
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
          <Card title="运行状态">
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="运行">{detail.id}</Descriptions.Item>
              <Descriptions.Item label="类型">{cnLabel(detail.evaluation_type)}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={statusColor(detail.status)}>{cnLabel(detail.status)}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="门禁">
                <Tag color={statusColor(detail.gate_status)}>{cnLabel(detail.gate_status)}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="项目">{detail.project_id}</Descriptions.Item>
              <Descriptions.Item label="版本">{detail.version_no}</Descriptions.Item>
              <Descriptions.Item label="配置哈希" span={2}>{detail.config_hash}</Descriptions.Item>
              <Descriptions.Item label="开始时间">{detail.started_at ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="结束时间">{detail.finished_at ?? '-'}</Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="变体配置矩阵" className="section-gap">
            <Table<EvaluationRunVariant>
              size="small"
              rowKey="id"
              dataSource={detail.variants}
              columns={[
                { title: '角色', dataIndex: 'role', render: (value: string) => <Tag>{cnLabel(value)}</Tag> },
                { title: '名称', dataIndex: 'name' },
                { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{cnLabel(value)}</Tag> },
                { title: '快照', dataIndex: 'configuration_snapshot_id', render: (value: string) => value.slice(0, 8) },
                { title: '配置哈希', dataIndex: 'configuration_hash', render: (value: string) => value.slice(0, 16) },
              ]}
            />
          </Card>

          <Card title="指标计分卡" className="section-gap" loading={metrics.isPending}>
            <Table<MetricResult>
              size="small"
              rowKey="id"
              dataSource={metrics.data ?? []}
              columns={[
                { title: '变体', dataIndex: 'variant_id', render: (value: string) => value.slice(0, 8) },
                { title: '指标', dataIndex: 'metric_name', render: (value: string) => cnLabel(value) },
                { title: '类别', dataIndex: 'category', render: (value: string) => <Tag>{cnLabel(value)}</Tag> },
                { title: '数值', dataIndex: 'value', render: (value: number) => metricValue(value) },
                { title: '单位', dataIndex: 'unit' },
              ]}
            />
          </Card>

          <Card title="基线对比与门禁" className="section-gap">
            {latestComparison ? (
              <Descriptions bordered size="small" column={2}>
                <Descriptions.Item label="门禁">
                  <Tag color={statusColor(latestComparison.gate_status)}>{cnLabel(latestComparison.gate_status)}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label="安全门禁">
                  <Tag color={statusColor(latestComparison.security_gate_status)}>
                    {cnLabel(latestComparison.security_gate_status)}
                  </Tag>
                </Descriptions.Item>
                <Descriptions.Item label="改善指标" span={2}>
                  <Space wrap>{latestComparison.improved_metrics.map((item) => <Tag color="green" key={item}>{item}</Tag>)}</Space>
                </Descriptions.Item>
                <Descriptions.Item label="回退指标" span={2}>
                  <Space wrap>{latestComparison.regressed_metrics.map((item) => <Tag color="red" key={item}>{item}</Tag>)}</Space>
                </Descriptions.Item>
                <Descriptions.Item label="失败门禁" span={2}>
                  <Space wrap>{latestComparison.failed_gates.map((item) => <Tag color="red" key={item}>{item}</Tag>)}</Space>
                </Descriptions.Item>
                <Descriptions.Item label="成本变化">{latestComparison.cost_change}</Descriptions.Item>
                <Descriptions.Item label="延迟变化">{latestComparison.latency_change}</Descriptions.Item>
              </Descriptions>
            ) : (
              <Typography.Text type="secondary">暂无对比结果。</Typography.Text>
            )}
          </Card>

          <Card title="失败项与安全违规" className="section-gap" loading={failures.isPending}>
            <Typography.Title level={5}>失败用例</Typography.Title>
            <Table<EvaluationFailure>
              size="small"
              rowKey="result_id"
              dataSource={failures.data ?? []}
              columns={[
                { title: '变体', dataIndex: 'variant_id', render: (value: string) => value.slice(0, 8) },
                { title: '用例', dataIndex: 'external_id' },
                { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{cnLabel(value)}</Tag> },
                { title: '原因', dataIndex: 'failure_reasons', render: (value: string[]) => value.join(', ') },
              ]}
            />
            <Typography.Title level={5}>安全违规</Typography.Title>
            <Table<MetricResult>
              size="small"
              rowKey="id"
              dataSource={securityMetrics}
              columns={[
                { title: '指标', dataIndex: 'metric_name', render: (value: string) => cnLabel(value) },
                { title: '数值', dataIndex: 'value', render: (value: number) => metricValue(value) },
                { title: '变体', dataIndex: 'variant_id', render: (value: string) => value.slice(0, 8) },
              ]}
            />
            <Typography.Title level={5}>成本与延迟</Typography.Title>
            <Table<MetricResult>
              size="small"
              rowKey="id"
              dataSource={costLatency}
              columns={[
                { title: '指标', dataIndex: 'metric_name', render: (value: string) => cnLabel(value) },
                { title: '数值', dataIndex: 'value', render: (value: number) => metricValue(value) },
                { title: '变体', dataIndex: 'variant_id', render: (value: string) => value.slice(0, 8) },
              ]}
            />
          </Card>

          <Card title="人工复核与提升" className="section-gap">
            <Space align="start" wrap>
              <Form<EvaluationReviewFormValue>
                layout="vertical"
                initialValues={{ decision: 'ACCEPTED', blind: true }}
                onFinish={(value) => review.mutate({
                  decision: value.decision,
                  blind: value.blind ?? true,
                  comments: value.comments,
                  annotations: {},
                })}
              >
                <Form.Item name="decision" label="复核决策" rules={[{ required: true }]}>
                  <Select
                    className="compact-select"
                    options={['ACCEPTED', 'REJECTED', 'CHANGES_REQUESTED'].map((value) => ({ value, label: cnLabel(value) }))}
                  />
                </Form.Item>
                <Form.Item name="comments" label="备注" rules={[{ required: true }]}>
                  <Input className="wide-input" />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={review.isPending}>记录复核</Button>
              </Form>
              <Form<PromotionDecisionFormValue>
                layout="vertical"
                initialValues={{ decision: 'APPROVED', target_environment: 'production' }}
                onFinish={(value) => promotion.mutate({
                  decision: value.decision,
                  reason: value.reason,
                  expected_version: detail.version_no,
                  target_environment: value.target_environment,
                })}
              >
                <Form.Item name="decision" label="提升决策" rules={[{ required: true }]}>
                  <Select
                    className="compact-select"
                    options={['APPROVED', 'REJECTED', 'PROMOTED', 'ROLLED_BACK'].map((value) => ({ value, label: cnLabel(value) }))}
                  />
                </Form.Item>
                <Form.Item name="reason" label="原因" rules={[{ required: true }]}>
                  <Input className="wide-input" />
                </Form.Item>
                <Form.Item name="target_environment" label="目标环境">
                  <Input />
                </Form.Item>
                <Button htmlType="submit" loading={promotion.isPending}>记录决策</Button>
              </Form>
            </Space>
          </Card>
        </>
      ) : null}
    </section>
  );
}
