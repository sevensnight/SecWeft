import { useQuery } from '@tanstack/react-query';
import type { TaskExecution } from '@vulnlab/shared-types';
import { Alert, Card, Select, Space, Table, Tag, Typography } from 'antd';
import { useState } from 'react';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { listTaskExecutions, listTasks } from '../../../services/api';

export function SandboxesPage() {
  const [taskId, setTaskId] = useState<string | null>(null);
  const tasks = useQuery({ queryKey: ['tasks'], queryFn: () => listTasks() });
  const selectedTaskId = taskId ?? tasks.data?.[0]?.id ?? null;
  const executions = useQuery({
    queryKey: ['task-executions', selectedTaskId],
    queryFn: () => listTaskExecutions(selectedTaskId ?? ''),
    enabled: Boolean(selectedTaskId),
  });
  const firstError = tasks.error ?? executions.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>Sandbox Center</Typography.Title>
        <Typography.Text type="secondary">
          Inspect task execution records and sandbox boundaries. The console does not run model-generated commands.
        </Typography.Text>
      </div>
      <Alert
        showIcon
        type="warning"
        message="Sandbox actions remain policy-gated"
        description="Future runtime operations must still pass backend policy, approval, audit, and isolation checks."
      />
      {tasks.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        void tasks.refetch();
        void executions.refetch();
      }} /> : null}
      <Card title="Execution ledger" className="section-gap">
        <Space direction="vertical" className="full-width">
          <Select
            showSearch
            className="wide-select"
            placeholder="Select task"
            value={selectedTaskId}
            options={(tasks.data ?? []).map((task) => ({ value: task.id, label: task.title }))}
            onChange={(value: string) => setTaskId(value)}
          />
          <Table<TaskExecution>
            size="small"
            rowKey="id"
            loading={executions.isPending}
            dataSource={executions.data ?? []}
            columns={[
              { title: 'Worker', dataIndex: 'worker_id' },
              { title: 'Fencing token', dataIndex: 'fencing_token' },
              { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag>{value}</Tag> },
              { title: 'Started', dataIndex: 'started_at' },
              { title: 'Finished', dataIndex: 'finished_at', render: (value: string | null) => value ?? '-' },
            ]}
          />
        </Space>
      </Card>
    </section>
  );
}
