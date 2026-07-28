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
  const hasSelectedTask = Boolean(selectedTaskId);
  const evidence = useQuery({
    queryKey: ['task-evidence', selectedTaskId],
    queryFn: () => listTaskEvidence(selectedTaskId ?? '', 100),
    enabled: hasSelectedTask,
  });
  const firstError = tasks.error ?? evidence.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>报告中心</Typography.Title>
        <Typography.Text type="secondary">
          在启用导出服务前，根据任务元数据、证据和引用检查报告准备度。
        </Typography.Text>
      </div>
      <Alert
        showIcon
        type="info"
        message="报告必须依赖可复核证据"
        description="模型文本本身不能作为证明；报告必须引用证据、上下文、策略和审批记录。"
      />
      {tasks.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        void tasks.refetch();
        if (hasSelectedTask) void evidence.refetch();
      }} /> : null}
      <Card title="报告输入" className="section-gap">
        <Space direction="vertical" className="full-width">
          <Select
            showSearch
            className="wide-select"
            placeholder="选择任务"
            value={selectedTaskId}
            disabled={!tasks.isPending && !hasSelectedTask}
            notFoundContent="暂无任务"
            options={(tasks.data ?? []).map((task) => ({ value: task.id, label: task.title }))}
            onChange={(value: string) => setTaskId(value)}
          />
          <Statistic title="证据条目" value={evidence.data?.length ?? 0} />
          {tasks.isSuccess && !hasSelectedTask ? (
            <Alert
              showIcon
              type="info"
              message="暂无可用于报告的任务"
              description="请先在任务中心创建任务；任务产生证据后，报告中心会显示证据准备度。"
            />
          ) : null}
        </Space>
      </Card>
      <Card title="证据" className="section-gap" loading={hasSelectedTask && evidence.isLoading}>
        <List
          dataSource={evidence.data ?? []}
          locale={{ emptyText: '暂无证据' }}
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
