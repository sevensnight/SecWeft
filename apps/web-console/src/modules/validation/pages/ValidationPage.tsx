import { useMutation, useQuery } from '@tanstack/react-query';
import type { ValidationPlan, ValidationPlanCreate } from '@vulnlab/shared-types';
import { App, Button, Card, Form, Input, InputNumber, Select, Space, Table, Tag, Typography } from 'antd';
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

interface PlanFormValue {
  host: string;
  objective: string;
  path?: string;
  port: number;
}

export function ValidationPage() {
  const { message } = App.useApp();
  const [taskId, setTaskId] = useState<string | null>(null);
  const tasks = useQuery({ queryKey: ['tasks'], queryFn: () => listTasks() });
  const selectedTaskId = taskId ?? tasks.data?.[0]?.id ?? null;
  const plans = useQuery({
    queryKey: ['validation-plans', selectedTaskId],
    queryFn: () => listTaskValidationPlans(selectedTaskId ?? ''),
    enabled: Boolean(selectedTaskId),
  });
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
      reason: approved ? 'Approved from P7 review console' : 'Rejected from P7 review console',
    }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['validation-plans', selectedTaskId] });
      message.success('Review saved.');
    },
  });
  const firstError = tasks.error ?? plans.error ?? createPlan.error ?? submitPlan.error ?? reviewPlan.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>Validation Center</Typography.Title>
        <Typography.Text type="secondary">
          Create non-destructive validation plan drafts, submit them, and review approvals without executing them.
        </Typography.Text>
      </div>
      {tasks.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        createPlan.reset();
        submitPlan.reset();
        reviewPlan.reset();
        void tasks.refetch();
        void plans.refetch();
      }} /> : null}
      <Card title="Task">
        <Select
          showSearch
          className="wide-select"
          placeholder="Select task"
          value={selectedTaskId}
          options={(tasks.data ?? []).map((task) => ({
            value: task.id,
            label: `${task.title} · ${task.approval_status}`,
          }))}
          onChange={(value: string) => setTaskId(value)}
        />
      </Card>
      <Card title="Create draft plan" className="section-gap">
        <Form<PlanFormValue>
          layout="vertical"
          disabled={!selectedTaskId}
          initialValues={{ objective: 'Confirm authorized defensive reachability only', host: '127.0.0.1', port: 65534, path: '/' }}
          onFinish={(value) => {
            createPlan.mutate({
              objectives: [value.objective],
              steps: [{
                kind: value.path ? 'http_request' : 'tcp_connect',
                host: value.host,
                port: value.port,
                method: value.path ? 'GET' : null,
                path: value.path || null,
                expected_status: value.path ? [200, 401, 403, 404] : [],
                body_pattern: null,
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
            <Form.Item label=" ">
              <Button type="primary" htmlType="submit" loading={createPlan.isPending}>Create draft</Button>
            </Form.Item>
          </Space>
        </Form>
      </Card>
      <Card title="Validation ledger" className="section-gap" loading={plans.isPending}>
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
                </Space>
              ),
            },
          ]}
        />
      </Card>
    </section>
  );
}
