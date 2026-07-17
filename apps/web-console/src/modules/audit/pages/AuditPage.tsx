import { useQuery } from '@tanstack/react-query';
import type { AuditEvent } from '@vulnlab/shared-types';
import { Card, Table, Tag, Typography } from 'antd';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { listAuditEvents } from '../../../services/api';

export function AuditPage() {
  const audit = useQuery({
    queryKey: ['audit', 'events'],
    queryFn: () => listAuditEvents(200),
    staleTime: 10_000,
  });

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>Audit Center</Typography.Title>
        <Typography.Text type="secondary">
          Append-only audit event view for permissions, policy decisions, model calls, tasks, RAG, and validation plans.
        </Typography.Text>
      </div>
      {audit.isPending ? <LoadingState /> : null}
      {audit.isError ? <QueryErrorState error={audit.error} onRetry={() => void audit.refetch()} /> : null}
      {audit.isSuccess ? (
        <Card>
          <Table<AuditEvent>
            size="small"
            rowKey="id"
            dataSource={audit.data}
            pagination={{ pageSize: 15 }}
            columns={[
              { title: 'Time', dataIndex: 'occurred_at' },
              { title: 'Actor', dataIndex: 'actor_id', ellipsis: true },
              { title: 'Action', dataIndex: 'action' },
              { title: 'Resource', render: (_: unknown, record: AuditEvent) => `${record.resource_type}:${record.resource_id}` },
              { title: 'Outcome', dataIndex: 'outcome', render: (value: string) => <Tag>{value}</Tag> },
              { title: 'Trace', dataIndex: 'trace_id', ellipsis: true },
            ]}
          />
        </Card>
      ) : null}
    </section>
  );
}
