import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from '@tanstack/react-router';
import type { TaskEvent } from '@vulnlab/shared-types';
import { StatusPill } from '@vulnlab/ui-components';
import { Alert, Button, Card, Descriptions, Flex, List, Space, Tag, Typography } from 'antd';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnLabel } from '../../../i18n/formatters';
import { taskEventsQuery, taskQuery } from '../api/queries';
import { useTaskEventStream } from '../hooks/useTaskEventStream';

function mergeEvents(persisted: TaskEvent[], streamed: TaskEvent[]): TaskEvent[] {
  return [...new Map([...persisted, ...streamed].map((event) => [event.id, event])).values()]
    .sort((left, right) => left.id - right.id);
}

export function TaskDetailPage() {
  const { taskId } = useParams({ from: '/tasks/$taskId' });
  const task = useQuery(taskQuery(taskId));
  const persistedEvents = useQuery(taskEventsQuery(taskId));
  const stream = useTaskEventStream(taskId);
  const events = mergeEvents(persistedEvents.data ?? [], stream.events);

  if (task.isPending) return <LoadingState />;
  if (task.isError) return <QueryErrorState error={task.error} onRetry={() => void task.refetch()} />;

  return (
    <section>
      <Flex justify="space-between" align="center" wrap gap="middle" className="page-title-row">
        <div>
          <Typography.Title level={2}>{task.data.title}</Typography.Title>
          <Space>
            <StatusPill status={task.data.status} label={cnLabel(task.data.status)} />
            <Tag color={stream.state === 'open' ? 'green' : 'default'}>
              事件流 {stream.state === 'open' ? '已连接' : '已关闭'}
            </Tag>
          </Space>
        </div>
        <Link to="/tasks"><Button>返回任务中心</Button></Link>
      </Flex>
      <div className="detail-grid">
        <Card title="任务投影">
          <Descriptions column={1} size="small">
            <Descriptions.Item label="目标">{task.data.target}</Descriptions.Item>
            <Descriptions.Item label="意图">{task.data.intent}</Descriptions.Item>
            <Descriptions.Item label="审批">{cnLabel(task.data.approval_status)}</Descriptions.Item>
            <Descriptions.Item label="范围 ID">{task.data.scope_id}</Descriptions.Item>
            <Descriptions.Item label="更新时间">{task.data.updated_at}</Descriptions.Item>
          </Descriptions>
        </Card>
        <Card title="实时事件">
          {persistedEvents.isError ? <Alert type="warning" showIcon message={persistedEvents.error.message} /> : null}
          <List
            className="event-list"
            locale={{ emptyText: '暂无事件' }}
            dataSource={events.slice().reverse()}
            renderItem={(event) => (
              <List.Item key={event.id}>
                <List.Item.Meta
                  title={<Space><Typography.Text code>#{event.id}</Typography.Text>{cnLabel(event.event_type)}</Space>}
                  description={new Date(event.created_at).toLocaleString()}
                />
              </List.Item>
            )}
          />
        </Card>
      </div>
    </section>
  );
}
