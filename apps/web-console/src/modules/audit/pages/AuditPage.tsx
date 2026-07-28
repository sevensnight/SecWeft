import { useQuery } from '@tanstack/react-query';
import type { AuditEvent } from '@vulnlab/shared-types';
import { Alert, Card, Table, Tag, Typography } from 'antd';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { authMode } from '../../../auth/config';
import { cnLabel } from '../../../i18n/formatters';
import { listAuditEvents } from '../../../services/api';

export function AuditPage() {
  const auditEnabled = authMode === 'oidc';
  const audit = useQuery({
    queryKey: ['audit', 'events'],
    queryFn: () => listAuditEvents(200),
    enabled: auditEnabled,
    staleTime: 10_000,
  });

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>审计中心</Typography.Title>
        <Typography.Text type="secondary">
          查看权限、策略判定、模型调用、任务、知识库和验证计划的追加式审计事件。
        </Typography.Text>
      </div>
      {!auditEnabled ? (
        <Alert
          showIcon
          type="info"
          message="审计中心需要 OIDC 模式"
          description="当前是 API Key 兼容模式，后端不会开放租户级审计事件接口；请切换到 OIDC 模式后查看完整审计。"
        />
      ) : null}
      {audit.isLoading ? <LoadingState /> : null}
      {audit.isError ? <QueryErrorState error={audit.error} onRetry={() => void audit.refetch()} /> : null}
      {audit.isSuccess ? (
        <Card>
          <Table<AuditEvent>
            size="small"
            rowKey="id"
            dataSource={audit.data}
            pagination={{ pageSize: 15 }}
            columns={[
              { title: '时间', dataIndex: 'occurred_at' },
              { title: '操作者', dataIndex: 'actor_id', ellipsis: true },
              { title: '动作', dataIndex: 'action' },
              { title: '资源', render: (_: unknown, record: AuditEvent) => `${record.resource_type}:${record.resource_id}` },
              { title: '结果', dataIndex: 'outcome', render: (value: string) => <Tag>{cnLabel(value)}</Tag> },
              { title: '追踪 ID', dataIndex: 'trace_id', ellipsis: true },
            ]}
          />
        </Card>
      ) : null}
    </section>
  );
}
