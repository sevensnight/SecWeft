import { useQuery } from '@tanstack/react-query';
import { Alert, Card, List, Select, Space, Statistic, Typography } from 'antd';
import { useState } from 'react';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { listTaskEvidence, listTasks } from '../../../services/api';

export function ReportsPage() {
  const [taskId, setTaskId] = useState<string | null>(null);
  const tasks = useQuery({ queryKey: ['tasks'], queryFn: () => listTasks() });
  const selectedTaskId = taskId ?? tasks.data?.[0]?.id ?? null;
  const evidence = useQuery({
    queryKey: ['task-evidence', selectedTaskId],
    queryFn: () => listTaskEvidence(selectedTaskId ?? '', 100),
    enabled: Boolean(selectedTaskId),
  });
  const firstError = tasks.error ?? evidence.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>Report Center</Typography.Title>
        <Typography.Text type="secondary">
          Check report readiness from task metadata, evidence, and citations before export services are enabled.
        </Typography.Text>
      </div>
      <Alert
        showIcon
        type="info"
        message="Reports require reviewable evidence"
        description="Model text alone is not accepted as proof. Reports must cite evidence, context, policy, and approval records."
      />
      {tasks.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        void tasks.refetch();
        void evidence.refetch();
      }} /> : null}
      <Card title="Report inputs" className="section-gap">
        <Space direction="vertical" className="full-width">
          <Select
            showSearch
            className="wide-select"
            placeholder="Select task"
            value={selectedTaskId}
            options={(tasks.data ?? []).map((task) => ({ value: task.id, label: task.title }))}
            onChange={(value: string) => setTaskId(value)}
          />
          <Statistic title="Evidence items" value={evidence.data?.length ?? 0} />
        </Space>
      </Card>
      <Card title="Evidence" className="section-gap" loading={evidence.isPending}>
        <List
          dataSource={evidence.data ?? []}
          locale={{ emptyText: 'No evidence' }}
          renderItem={(item) => (
            <List.Item>
              <List.Item.Meta
                title={item.title}
                description={`${item.source_type}:${item.source_ref} · ${item.content_hash}`}
              />
            </List.Item>
          )}
        />
      </Card>
    </section>
  );
}
