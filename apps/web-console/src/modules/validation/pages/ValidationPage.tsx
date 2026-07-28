import { useMutation, useQuery } from '@tanstack/react-query';
import type {
  ValidationExecution,
  ValidationExecutionEvidence,
  ValidationExecutionEvent,
  ValidationPlan,
  ValidationPlanCreate,
} from '@vulnlab/shared-types';
import {
  Alert,
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
  Timeline,
  Typography,
} from 'antd';
import { useState } from 'react';

import { queryClient } from '../../../app/query-client';
import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnLabel } from '../../../i18n/formatters';
import {
  createTaskValidationPlan,
  listTaskValidationPlans,
  listTasks,
  reviewValidationPlan,
  submitValidationPlan,
} from '../../../services/api';
import {
  cancelValidationExecution,
  createValidationExecution,
  listValidationExecutionEvents,
  listValidationExecutionEvidence,
  listValidationExecutions,
  listValidationTemplates,
  retryValidationExecution,
  reviewValidationExecution,
} from '../../../services/validation-executions';

interface PlanFormValue {
  bodyPattern?: string;
  host: string;
  objective: string;
  path?: string;
  port: number;
}

const TERMINAL = new Set([
  'SUCCEEDED',
  'FAILED',
  'CANCELLED',
  'EXPIRED',
  'POLICY_REJECTED',
  'APPROVAL_REVOKED',
  'SCOPE_INVALID',
  'SANDBOX_FAILED',
  'RESOURCE_EXCEEDED',
  'EXECUTION_TIMEOUT',
  'EVIDENCE_INCOMPLETE',
]);

function statusColor(status: string) {
  if (status === 'SUCCEEDED') return 'green';
  if (['FAILED', 'POLICY_REJECTED', 'APPROVAL_REVOKED', 'SCOPE_INVALID', 'SANDBOX_FAILED'].includes(status)) return 'red';
  if (status === 'CANCELLED') return 'orange';
  if (TERMINAL.has(status)) return 'volcano';
  return 'blue';
}

export function ValidationPage() {
  const { message } = App.useApp();
  const [taskId, setTaskId] = useState<string | null>(null);
  const [executionId, setExecutionId] = useState<string | null>(null);
  const tasks = useQuery({ queryKey: ['tasks'], queryFn: () => listTasks() });
  const selectedTaskId = taskId ?? tasks.data?.[0]?.id ?? null;
  const hasSelectedTask = Boolean(selectedTaskId);
  const plans = useQuery({
    queryKey: ['validation-plans', selectedTaskId],
    queryFn: () => listTaskValidationPlans(selectedTaskId ?? ''),
    enabled: hasSelectedTask,
  });
  const templates = useQuery({
    queryKey: ['validation-templates'],
    queryFn: () => listValidationTemplates(),
  });
  const executions = useQuery({
    queryKey: ['validation-executions', selectedTaskId],
    queryFn: () => listValidationExecutions(100, selectedTaskId),
    enabled: hasSelectedTask,
    refetchInterval: 3000,
  });
  const selectedExecution = executions.data?.find((item) => item.id === executionId) ?? executions.data?.[0] ?? null;
  const hasSelectedExecution = Boolean(selectedExecution?.id);
  const events = useQuery({
    queryKey: ['validation-execution-events', selectedExecution?.id],
    queryFn: () => listValidationExecutionEvents(selectedExecution?.id ?? ''),
    enabled: hasSelectedExecution,
    refetchInterval: selectedExecution && !TERMINAL.has(selectedExecution.status) ? 1500 : false,
  });
  const evidence = useQuery({
    queryKey: ['validation-execution-evidence', selectedExecution?.id],
    queryFn: () => listValidationExecutionEvidence(selectedExecution?.id ?? ''),
    enabled: hasSelectedExecution,
    refetchInterval: selectedExecution && !TERMINAL.has(selectedExecution.status) ? 3000 : false,
  });

  const invalidateExecutionQueries = async (newExecutionId?: string) => {
    if (newExecutionId) setExecutionId(newExecutionId);
    await queryClient.invalidateQueries({ queryKey: ['validation-executions', selectedTaskId] });
    await queryClient.invalidateQueries({ queryKey: ['validation-execution-events'] });
    await queryClient.invalidateQueries({ queryKey: ['validation-execution-evidence'] });
  };

  const createPlan = useMutation({
    mutationFn: (value: ValidationPlanCreate) => createTaskValidationPlan(selectedTaskId ?? '', value),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['validation-plans', selectedTaskId] });
      message.success('验证计划已创建。');
    },
  });
  const submitPlan = useMutation({
    mutationFn: submitValidationPlan,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['validation-plans', selectedTaskId] });
      message.success('验证计划已提交。');
    },
  });
  const reviewPlan = useMutation({
    mutationFn: ({ id, approved }: { approved: boolean; id: string }) => reviewValidationPlan(id, {
      approved,
      reason: approved ? '从验证控制台批准' : '从验证控制台拒绝',
    }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['validation-plans', selectedTaskId] });
      message.success('复核结果已保存。');
    },
  });
  const queueExecution = useMutation({
    mutationFn: (planId: string) => createValidationExecution(planId, templates.data?.[0]?.id ?? 'http.response'),
    onSuccess: async (execution) => {
      await invalidateExecutionQueries(execution.id);
      message.success('验证执行已入队。');
    },
  });
  const cancelExecution = useMutation({
    mutationFn: (id: string) => cancelValidationExecution(id),
    onSuccess: async (execution) => {
      await invalidateExecutionQueries(execution.id);
      message.success('取消请求已记录。');
    },
  });
  const retryExecution = useMutation({
    mutationFn: (id: string) => retryValidationExecution(id),
    onSuccess: async (execution) => {
      await invalidateExecutionQueries(execution.id);
      message.success('重试已入队。');
    },
  });
  const executionReview = useMutation({
    mutationFn: ({ id, accepted }: { accepted: boolean; id: string }) => reviewValidationExecution(id, {
      accepted,
      reason: accepted ? '从验证控制台接受证据' : '从验证控制台拒绝证据',
    }),
    onSuccess: async (execution) => {
      await invalidateExecutionQueries(execution.id);
      message.success('执行复核已保存。');
    },
  });
  const firstError = tasks.error
    ?? plans.error
    ?? templates.error
    ?? executions.error
    ?? events.error
    ?? evidence.error
    ?? createPlan.error
    ?? submitPlan.error
    ?? reviewPlan.error
    ?? queueExecution.error
    ?? cancelExecution.error
    ?? retryExecution.error
    ?? executionReview.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>验证中心</Typography.Title>
        <Typography.Text type="secondary">
          创建已审批验证计划、将受控执行入队、复核策略和沙箱状态，并查看标准化证据。
        </Typography.Text>
      </div>
      {tasks.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        createPlan.reset();
        submitPlan.reset();
        reviewPlan.reset();
        queueExecution.reset();
        cancelExecution.reset();
        retryExecution.reset();
        executionReview.reset();
        void tasks.refetch();
        void templates.refetch();
        if (hasSelectedTask) {
          void plans.refetch();
          void executions.refetch();
        }
        if (hasSelectedExecution) {
          void events.refetch();
          void evidence.refetch();
        }
      }} /> : null}
      <Card title="任务">
        <Select
          showSearch
          className="wide-select"
          placeholder="选择任务"
          value={selectedTaskId}
          disabled={!tasks.isPending && !hasSelectedTask}
          notFoundContent="暂无任务"
          options={(tasks.data ?? []).map((task) => ({
            value: task.id,
            label: `${task.title} / ${cnLabel(task.approval_status)}`,
          }))}
          onChange={(value: string) => {
            setTaskId(value);
            setExecutionId(null);
          }}
        />
      </Card>
      {tasks.isSuccess && !hasSelectedTask ? (
        <Alert
          showIcon
          type="info"
          message="暂无可验证的任务"
          description="请先在任务中心创建任务；任务创建后才能起草验证计划、入队执行并查看证据。"
          className="section-gap"
        />
      ) : null}
      <Card title="创建草稿计划" className="section-gap">
        <Form<PlanFormValue>
          layout="vertical"
          disabled={!selectedTaskId}
          initialValues={{
            bodyPattern: '',
            host: '127.0.0.1',
            objective: '确认已授权 HTTP 响应特征',
            path: '/',
            port: 65534,
          }}
          onFinish={(value) => {
            const hasPath = Boolean(value.path);
            createPlan.mutate({
              objectives: [value.objective],
              steps: [{
                kind: hasPath ? 'http_request' : 'tcp_connect',
                host: value.host,
                port: value.port,
                method: hasPath ? 'GET' : null,
                path: value.path || null,
                expected_status: hasPath ? [200, 401, 403, 404] : [],
                body_pattern: value.bodyPattern || null,
              }],
              rollback: ['未执行状态变更'],
            });
          }}
        >
          <Space wrap align="start">
            <Form.Item name="objective" label="目标" rules={[{ required: true }]}>
              <Input className="wide-input" />
            </Form.Item>
            <Form.Item name="host" label="主机" rules={[{ required: true }]}>
              <Input />
            </Form.Item>
            <Form.Item name="port" label="端口" rules={[{ required: true }]}>
              <InputNumber min={1} max={65535} />
            </Form.Item>
            <Form.Item name="path" label="HTTP 路径">
              <Input />
            </Form.Item>
            <Form.Item name="bodyPattern" label="响应内容模式">
              <Input />
            </Form.Item>
            <Form.Item label=" ">
              <Button type="primary" htmlType="submit" loading={createPlan.isPending}>创建草稿</Button>
            </Form.Item>
          </Space>
        </Form>
      </Card>
      <Card title="验证计划" className="section-gap" loading={hasSelectedTask && plans.isLoading}>
        <Table<ValidationPlan>
          size="small"
          rowKey="id"
          dataSource={plans.data ?? []}
          columns={[
            { title: '状态', dataIndex: 'status', render: (value: string) => <Tag>{cnLabel(value)}</Tag> },
            { title: '计划哈希', dataIndex: 'plan_hash', ellipsis: true },
            { title: '策略判定数', dataIndex: 'policy_decision_ids', render: (values: string[]) => values.length },
            { title: '提交时间', dataIndex: 'submitted_at', render: (value: string | null) => value ?? '-' },
            { title: '复核原因', dataIndex: 'review_reason', render: (value: string | null) => value ?? '-' },
            {
              title: '操作',
              render: (_: unknown, record: ValidationPlan) => (
                <Space>
                  <Button size="small" disabled={record.status !== 'draft'} loading={submitPlan.isPending} onClick={() => submitPlan.mutate(record.id)}>提交</Button>
                  <Button size="small" disabled={record.status !== 'submitted'} loading={reviewPlan.isPending} onClick={() => reviewPlan.mutate({ id: record.id, approved: true })}>批准</Button>
                  <Button size="small" danger disabled={record.status !== 'submitted'} loading={reviewPlan.isPending} onClick={() => reviewPlan.mutate({ id: record.id, approved: false })}>拒绝</Button>
                  <Button size="small" type="primary" disabled={record.status !== 'approved'} loading={queueExecution.isPending} onClick={() => queueExecution.mutate(record.id)}>执行入队</Button>
                </Space>
              ),
            },
          ]}
        />
      </Card>
      <Card title="执行时间线" className="section-gap" loading={hasSelectedTask && executions.isLoading}>
        <Space direction="vertical" className="full-width">
          <Table<ValidationExecution>
            size="small"
            rowKey="id"
            dataSource={executions.data ?? []}
            onRow={(record) => ({ onClick: () => setExecutionId(record.id) })}
            columns={[
              { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{cnLabel(value)}</Tag> },
              { title: '模板', dataIndex: 'template_id' },
              { title: '追踪 ID', dataIndex: 'trace_id', ellipsis: true },
              { title: '沙箱', dataIndex: 'sandbox_id', ellipsis: true },
              { title: '策略判定', dataIndex: 'policy_decision_id', ellipsis: true },
              { title: '审批', dataIndex: 'approval_id', ellipsis: true },
              { title: '创建时间', dataIndex: 'created_at' },
              {
                title: '操作',
                render: (_: unknown, record: ValidationExecution) => (
                  <Space>
                    <Button size="small" disabled={TERMINAL.has(record.status)} loading={cancelExecution.isPending} onClick={() => cancelExecution.mutate(record.id)}>取消</Button>
                    <Button size="small" disabled={!TERMINAL.has(record.status) || record.status === 'SUCCEEDED'} loading={retryExecution.isPending} onClick={() => retryExecution.mutate(record.id)}>重试</Button>
                    <Button size="small" disabled={!TERMINAL.has(record.status)} loading={executionReview.isPending} onClick={() => executionReview.mutate({ id: record.id, accepted: true })}>接受证据</Button>
                  </Space>
                ),
              },
            ]}
          />
          {selectedExecution ? (
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="执行实例">{selectedExecution.id}</Descriptions.Item>
              <Descriptions.Item label="复核">{cnLabel(selectedExecution.review_decision, '待复核')}</Descriptions.Item>
              <Descriptions.Item label="队列消息">{selectedExecution.queue_message_id ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="错误">{selectedExecution.error ?? '-'}</Descriptions.Item>
            </Descriptions>
          ) : null}
          <Timeline
            items={(events.data ?? []).map((event: ValidationExecutionEvent) => ({
              color: statusColor(event.status),
              children: `${event.created_at} / ${cnLabel(event.status)} / ${cnLabel(event.event_type)}`,
            }))}
          />
        </Space>
      </Card>
      <Card title="证据" className="section-gap" loading={hasSelectedExecution && evidence.isLoading}>
        <Table<ValidationExecutionEvidence>
          size="small"
          rowKey="id"
          dataSource={evidence.data ?? []}
          columns={[
            { title: '标题', dataIndex: 'title' },
            { title: '产物引用', dataIndex: 'artifact_ref', ellipsis: true },
            { title: 'SHA-256', dataIndex: 'content_sha256', ellipsis: true },
            { title: '证据条目', dataIndex: 'evidence_item_id', ellipsis: true },
            { title: '创建时间', dataIndex: 'created_at' },
          ]}
        />
      </Card>
    </section>
  );
}
