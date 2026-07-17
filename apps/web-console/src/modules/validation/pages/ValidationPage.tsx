import { useMutation, useQuery } from '@tanstack/react-query';
import type {
  ValidationExecution,
  ValidationExecutionEvidence,
  ValidationExecutionEvent,
  ValidationPlan,
  ValidationPlanCreate,
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
  Timeline,
  Typography,
} from 'antd';
import { useState } from 'react';

import { queryClient } from '../../../app/query-client';
import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
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
  const plans = useQuery({
    queryKey: ['validation-plans', selectedTaskId],
    queryFn: () => listTaskValidationPlans(selectedTaskId ?? ''),
    enabled: Boolean(selectedTaskId),
  });
  const templates = useQuery({
    queryKey: ['validation-templates'],
    queryFn: () => listValidationTemplates(),
  });
  const executions = useQuery({
    queryKey: ['validation-executions', selectedTaskId],
    queryFn: () => listValidationExecutions(100, selectedTaskId),
    enabled: Boolean(selectedTaskId),
    refetchInterval: 3000,
  });
  const selectedExecution = executions.data?.find((item) => item.id === executionId) ?? executions.data?.[0] ?? null;
  const events = useQuery({
    queryKey: ['validation-execution-events', selectedExecution?.id],
    queryFn: () => listValidationExecutionEvents(selectedExecution?.id ?? ''),
    enabled: Boolean(selectedExecution?.id),
    refetchInterval: selectedExecution && !TERMINAL.has(selectedExecution.status) ? 1500 : false,
  });
  const evidence = useQuery({
    queryKey: ['validation-execution-evidence', selectedExecution?.id],
    queryFn: () => listValidationExecutionEvidence(selectedExecution?.id ?? ''),
    enabled: Boolean(selectedExecution?.id),
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
      message.success('Validation plan created.');
    },
  });
  const submitPlan = useMutation({
    mutationFn: submitValidationPlan,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['validation-plans', selectedTaskId] });
      message.success('Validation plan submitted.');
    },
  });
  const reviewPlan = useMutation({
    mutationFn: ({ id, approved }: { approved: boolean; id: string }) => reviewValidationPlan(id, {
      approved,
      reason: approved ? 'Approved from P9 validation console' : 'Rejected from P9 validation console',
    }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['validation-plans', selectedTaskId] });
      message.success('Review saved.');
    },
  });
  const queueExecution = useMutation({
    mutationFn: (planId: string) => createValidationExecution(planId, templates.data?.[0]?.id ?? 'http.response'),
    onSuccess: async (execution) => {
      await invalidateExecutionQueries(execution.id);
      message.success('Validation execution queued.');
    },
  });
  const cancelExecution = useMutation({
    mutationFn: (id: string) => cancelValidationExecution(id),
    onSuccess: async (execution) => {
      await invalidateExecutionQueries(execution.id);
      message.success('Cancellation recorded.');
    },
  });
  const retryExecution = useMutation({
    mutationFn: (id: string) => retryValidationExecution(id),
    onSuccess: async (execution) => {
      await invalidateExecutionQueries(execution.id);
      message.success('Retry queued.');
    },
  });
  const executionReview = useMutation({
    mutationFn: ({ id, accepted }: { accepted: boolean; id: string }) => reviewValidationExecution(id, {
      accepted,
      reason: accepted ? 'Accepted from P9 validation console' : 'Rejected from P9 validation console',
    }),
    onSuccess: async (execution) => {
      await invalidateExecutionQueries(execution.id);
      message.success('Execution review saved.');
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
        <Typography.Title level={2}>Validation Center</Typography.Title>
        <Typography.Text type="secondary">
          Create approved validation plans, queue controlled executions, review policy/sandbox state, and inspect evidence.
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
        void plans.refetch();
        void templates.refetch();
        void executions.refetch();
        void events.refetch();
        void evidence.refetch();
      }} /> : null}
      <Card title="Task">
        <Select
          showSearch
          className="wide-select"
          placeholder="Select task"
          value={selectedTaskId}
          options={(tasks.data ?? []).map((task) => ({
            value: task.id,
            label: `${task.title} / ${task.approval_status}`,
          }))}
          onChange={(value: string) => {
            setTaskId(value);
            setExecutionId(null);
          }}
        />
      </Card>
      <Card title="Create draft plan" className="section-gap">
        <Form<PlanFormValue>
          layout="vertical"
          disabled={!selectedTaskId}
          initialValues={{
            bodyPattern: '',
            host: '127.0.0.1',
            objective: 'Confirm approved HTTP response characteristics',
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
              rollback: ['No state change performed'],
            });
          }}
        >
          <Space wrap align="start">
            <Form.Item name="objective" label="Objective" rules={[{ required: true }]}>
              <Input className="wide-input" />
            </Form.Item>
            <Form.Item name="host" label="Host" rules={[{ required: true }]}>
              <Input />
            </Form.Item>
            <Form.Item name="port" label="Port" rules={[{ required: true }]}>
              <InputNumber min={1} max={65535} />
            </Form.Item>
            <Form.Item name="path" label="HTTP Path">
              <Input />
            </Form.Item>
            <Form.Item name="bodyPattern" label="Body pattern">
              <Input />
            </Form.Item>
            <Form.Item label=" ">
              <Button type="primary" htmlType="submit" loading={createPlan.isPending}>Create draft</Button>
            </Form.Item>
          </Space>
        </Form>
      </Card>
      <Card title="Validation plans" className="section-gap" loading={plans.isPending}>
        <Table<ValidationPlan>
          size="small"
          rowKey="id"
          dataSource={plans.data ?? []}
          columns={[
            { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag>{value}</Tag> },
            { title: 'Plan hash', dataIndex: 'plan_hash', ellipsis: true },
            { title: 'Policy decisions', dataIndex: 'policy_decision_ids', render: (values: string[]) => values.length },
            { title: 'Submitted', dataIndex: 'submitted_at', render: (value: string | null) => value ?? '-' },
            { title: 'Review reason', dataIndex: 'review_reason', render: (value: string | null) => value ?? '-' },
            {
              title: 'Actions',
              render: (_: unknown, record: ValidationPlan) => (
                <Space>
                  <Button size="small" disabled={record.status !== 'draft'} loading={submitPlan.isPending} onClick={() => submitPlan.mutate(record.id)}>Submit</Button>
                  <Button size="small" disabled={record.status !== 'submitted'} loading={reviewPlan.isPending} onClick={() => reviewPlan.mutate({ id: record.id, approved: true })}>Approve</Button>
                  <Button size="small" danger disabled={record.status !== 'submitted'} loading={reviewPlan.isPending} onClick={() => reviewPlan.mutate({ id: record.id, approved: false })}>Reject</Button>
                  <Button size="small" type="primary" disabled={record.status !== 'approved'} loading={queueExecution.isPending} onClick={() => queueExecution.mutate(record.id)}>Queue execution</Button>
                </Space>
              ),
            },
          ]}
        />
      </Card>
      <Card title="Execution timeline" className="section-gap" loading={executions.isPending}>
        <Space direction="vertical" className="full-width">
          <Table<ValidationExecution>
            size="small"
            rowKey="id"
            dataSource={executions.data ?? []}
            onRow={(record) => ({ onClick: () => setExecutionId(record.id) })}
            columns={[
              { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{value}</Tag> },
              { title: 'Template', dataIndex: 'template_id' },
              { title: 'Trace', dataIndex: 'trace_id', ellipsis: true },
              { title: 'Sandbox', dataIndex: 'sandbox_id', ellipsis: true },
              { title: 'Policy decision', dataIndex: 'policy_decision_id', ellipsis: true },
              { title: 'Approval', dataIndex: 'approval_id', ellipsis: true },
              { title: 'Created', dataIndex: 'created_at' },
              {
                title: 'Actions',
                render: (_: unknown, record: ValidationExecution) => (
                  <Space>
                    <Button size="small" disabled={TERMINAL.has(record.status)} loading={cancelExecution.isPending} onClick={() => cancelExecution.mutate(record.id)}>Cancel</Button>
                    <Button size="small" disabled={!TERMINAL.has(record.status) || record.status === 'SUCCEEDED'} loading={retryExecution.isPending} onClick={() => retryExecution.mutate(record.id)}>Retry</Button>
                    <Button size="small" disabled={!TERMINAL.has(record.status)} loading={executionReview.isPending} onClick={() => executionReview.mutate({ id: record.id, accepted: true })}>Accept evidence</Button>
                  </Space>
                ),
              },
            ]}
          />
          {selectedExecution ? (
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="Execution">{selectedExecution.id}</Descriptions.Item>
              <Descriptions.Item label="Review">{selectedExecution.review_decision ?? 'pending'}</Descriptions.Item>
              <Descriptions.Item label="Queue message">{selectedExecution.queue_message_id ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="Error">{selectedExecution.error ?? '-'}</Descriptions.Item>
            </Descriptions>
          ) : null}
          <Timeline
            items={(events.data ?? []).map((event: ValidationExecutionEvent) => ({
              color: statusColor(event.status),
              children: `${event.created_at} / ${event.status} / ${event.event_type}`,
            }))}
          />
        </Space>
      </Card>
      <Card title="Evidence" className="section-gap" loading={evidence.isPending}>
        <Table<ValidationExecutionEvidence>
          size="small"
          rowKey="id"
          dataSource={evidence.data ?? []}
          columns={[
            { title: 'Title', dataIndex: 'title' },
            { title: 'Artifact', dataIndex: 'artifact_ref', ellipsis: true },
            { title: 'SHA-256', dataIndex: 'content_sha256', ellipsis: true },
            { title: 'Evidence item', dataIndex: 'evidence_item_id', ellipsis: true },
            { title: 'Created', dataIndex: 'created_at' },
          ]}
        />
      </Card>
    </section>
  );
}
