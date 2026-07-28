import { useQuery } from '@tanstack/react-query';
import type { TaskExecution, ValidationExecution } from '@vulnlab/shared-types';
import { Alert, Card, Descriptions, Select, Space, Table, Tag, Typography } from 'antd';
import { useState } from 'react';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnLabel } from '../../../i18n/formatters';
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
  const hasSelectedTask = Boolean(selectedTaskId);
  const taskExecutions = useQuery({
    queryKey: ['task-executions', selectedTaskId],
    queryFn: () => listTaskExecutions(selectedTaskId ?? ''),
    enabled: hasSelectedTask,
  });
  const validationExecutions = useQuery({
    queryKey: ['validation-executions', selectedTaskId],
    queryFn: () => listValidationExecutions(100, selectedTaskId),
    enabled: hasSelectedTask,
    refetchInterval: 3000,
  });
  const selectedExecution = validationExecutions.data?.find((item) => item.id === executionId)
    ?? validationExecutions.data?.[0]
    ?? null;
  const firstError = tasks.error ?? taskExecutions.error ?? validationExecutions.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>沙箱中心</Typography.Title>
        <Typography.Text type="secondary">
          查看任务执行记录和验证沙箱边界；控制台不会运行模型生成的命令。
        </Typography.Text>
      </div>
      <Alert
        showIcon
        type="warning"
        message="沙箱操作仍受策略约束"
        description="验证 Worker 在执行前必须重新检查审批、范围、策略、沙箱限制、证据完整性和审计元数据。"
      />
      {tasks.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        void tasks.refetch();
        if (hasSelectedTask) {
          void taskExecutions.refetch();
          void validationExecutions.refetch();
        }
      }} /> : null}
      <Card title="任务" className="section-gap">
        <Space direction="vertical" size={12} className="full-width">
          <Select
            showSearch
            className="wide-select"
            placeholder="选择任务"
            value={selectedTaskId}
            disabled={!tasks.isPending && !hasSelectedTask}
            notFoundContent="暂无任务"
            options={(tasks.data ?? []).map((task) => ({ value: task.id, label: task.title }))}
            onChange={(value: string) => {
              setTaskId(value);
              setExecutionId(null);
            }}
          />
          {tasks.isSuccess && !hasSelectedTask ? (
            <Alert
              showIcon
              type="info"
              message="暂无可查看的任务"
              description="请先创建任务；任务产生执行记录后，沙箱中心会展示验证沙箱和任务执行账本。"
            />
          ) : null}
        </Space>
      </Card>
      <Card title="验证沙箱" className="section-gap">
        <Space direction="vertical" className="full-width">
          <Table<ValidationExecution>
            size="small"
            rowKey="id"
            loading={hasSelectedTask && validationExecutions.isLoading}
            dataSource={validationExecutions.data ?? []}
            onRow={(record) => ({ onClick: () => setExecutionId(record.id) })}
            columns={[
              { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{cnLabel(value)}</Tag> },
              { title: '沙箱 ID', dataIndex: 'sandbox_id', ellipsis: true },
              { title: '模板', dataIndex: 'template_id' },
              { title: '策略判定', dataIndex: 'policy_decision_id', ellipsis: true },
              { title: '审批', dataIndex: 'approval_id', ellipsis: true },
              { title: '追踪 ID', dataIndex: 'trace_id', ellipsis: true },
              { title: '开始时间', dataIndex: 'started_at', render: (value: string | null) => value ?? '-' },
              { title: '结束时间', dataIndex: 'finished_at', render: (value: string | null) => value ?? '-' },
            ]}
          />
          {selectedExecution ? (
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="执行实例">{selectedExecution.id}</Descriptions.Item>
              <Descriptions.Item label="沙箱">{selectedExecution.sandbox_id}</Descriptions.Item>
              <Descriptions.Item label="队列消息">{selectedExecution.queue_message_id ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="人工复核">{cnLabel(selectedExecution.review_decision, '待复核')}</Descriptions.Item>
              <Descriptions.Item label="错误">{selectedExecution.error ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="结果">{selectedExecution.result?.matched === true ? '已匹配' : '待完成或失败'}</Descriptions.Item>
            </Descriptions>
          ) : null}
        </Space>
      </Card>
      <Card title="旧版任务执行账本" className="section-gap">
        <Table<TaskExecution>
          size="small"
          rowKey="id"
          loading={hasSelectedTask && taskExecutions.isLoading}
          dataSource={taskExecutions.data ?? []}
          columns={[
            { title: '工作节点', dataIndex: 'worker_id' },
            { title: '隔离令牌', dataIndex: 'fencing_token' },
            { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={statusColor(value)}>{cnLabel(value)}</Tag> },
            { title: '开始时间', dataIndex: 'started_at' },
            { title: '结束时间', dataIndex: 'finished_at', render: (value: string | null) => value ?? '-' },
          ]}
        />
      </Card>
    </section>
  );
}
