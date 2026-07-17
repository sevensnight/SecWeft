import { useQuery } from '@tanstack/react-query';
import type { TaskExecution, ValidationExecution } from '@vulnlab/shared-types';
import { Alert, Card, Descriptions, Select, Space, Table, Tag, Typography } from 'antd';
import { useState } from 'react';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { listTaskExecutions, listTasks } from '../../../services/api';
import { listValidationExecutions } from '../../../services/validation-executions';

function statusColor(status: string) {
  if (status === 'SUCCEEDED' || status === 'succeeded') return 'green';
  if (status === 'CANCELLED' || status === 'cancelled') return 'orange';
  if (status.includes('FAILED') || status === 'failed' || status.includes('REJECTED')) return 'red';
  return 'blue';
}

export function SandboxesPage() {
  const [taskId, setTaskId] = useState<string | null>(null);
  const [executionId, setExecutionId] = useState<string | null>(null);
  const tasks = useQuery({ queryKey: ['tasks'], queryFn: () => listTasks() });
  const selectedTaskId = taskId ?? tasks.data?.[0]?.id ?? null;
  const taskExecutions = useQuery({
    queryKey: ['task-executions', selectedTaskId],
    queryFn: () => listTaskExecutions(selectedTaskId ?? ''),
    enabled: Boolean(selectedTaskId),
  });
  const validationExecutions = useQuery({
    queryKey: ['validation-executions', selectedTaskId],
    queryFn: () => listValidationExecutions(100, selectedTaskId),
    enabled: Boolean(selectedTaskId),
    refetchInterval: 3000,
  });
  const selectedExecution = validationExecutions.data?.find((item) => item.id === executionId)
    ?? validationExecutions.data?.[0]
    ?? null;
  const firstError = tasks.error ?? taskExecutions.error ?? validationExecutions.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>Sandbox Center</Typography.Title>
        <Typography.Text type="secondary">
          Inspect task execution records and P9 validation sandbox boundaries. The console does not run model-generated commands.
        </Typography.Text>
      </div>
      <Alert
        showIcon
        type="warning"
        message="Sandbox actions remain policy-gated"
        description="Validation workers must re-check approval, scope, policy, sandbox limits, evidence integrity, and audit metadata before execution."
      />
      {tasks.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        void tasks.refetch();
        void taskExecutions.refetch();
        void validationExecutions.refetch();
      }} /> : null}
      <Card title="Task" className="section-gap">
        <Select
          showSearch
          className="wide-select"
          placeholder="Select task"
          value={selectedTaskId}
          options={(tasks.data ?? []).map((task) => ({ value: task.id, label: task.title }))}
          onChange={(value: string) => {
            setTaskId(value);
            setExecutionId(null);
          }}
        />
      </Card>
      <Card title="P9 validation sandboxes" className="section-gap">
        <Space direction="vertical" className="full-width">
          <Table<ValidationExecution>
            size="small"
            rowKey="id"
            loading={validationExecutions.isPending}
            dataSource={validationExecutions.data ?? []}
            onRow={(record) => ({ onClick: () => setExecutionId(record.id) })}
            columns={[
              { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{value}</Tag> },
              { title: 'Sandbox ID', dataIndex: 'sandbox_id', ellipsis: true },
              { title: 'Template', dataIndex: 'template_id' },
              { title: 'Policy decision', dataIndex: 'policy_decision_id', ellipsis: true },
              { title: 'Approval', dataIndex: 'approval_id', ellipsis: true },
              { title: 'Trace', dataIndex: 'trace_id', ellipsis: true },
              { title: 'Started', dataIndex: 'started_at', render: (value: string | null) => value ?? '-' },
              { title: 'Finished', dataIndex: 'finished_at', render: (value: string | null) => value ?? '-' },
            ]}
          />
          {selectedExecution ? (
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="Execution">{selectedExecution.id}</Descriptions.Item>
              <Descriptions.Item label="Sandbox">{selectedExecution.sandbox_id}</Descriptions.Item>
              <Descriptions.Item label="Queue message">{selectedExecution.queue_message_id ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="Review">{selectedExecution.review_decision ?? 'pending'}</Descriptions.Item>
              <Descriptions.Item label="Error">{selectedExecution.error ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="Result">{selectedExecution.result?.matched === true ? 'matched' : 'pending or failed'}</Descriptions.Item>
            </Descriptions>
          ) : null}
        </Space>
      </Card>
      <Card title="Legacy task execution ledger" className="section-gap">
        <Table<TaskExecution>
          size="small"
          rowKey="id"
          loading={taskExecutions.isPending}
          dataSource={taskExecutions.data ?? []}
          columns={[
            { title: 'Worker', dataIndex: 'worker_id' },
            { title: 'Fencing token', dataIndex: 'fencing_token' },
            { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{value}</Tag> },
            { title: 'Started', dataIndex: 'started_at' },
            { title: 'Finished', dataIndex: 'finished_at', render: (value: string | null) => value ?? '-' },
          ]}
        />
      </Card>
    </section>
  );
}
