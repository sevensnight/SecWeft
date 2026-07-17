import { useQuery } from '@tanstack/react-query';
import { Card, Flex, Input, Typography } from 'antd';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { tasksQuery } from '../api/queries';
import { TaskVirtualList } from '../components/TaskVirtualList';
import { useFilteredTasks } from '../hooks/useFilteredTasks';
import { useTaskViewStore } from '../stores/task-view';

export function TaskListPage() {
  const filter = useTaskViewStore((state) => state.filter);
  const setFilter = useTaskViewStore((state) => state.setFilter);
  const query = useQuery(tasksQuery());
  const filtered = useFilteredTasks(query.data ?? [], filter);

  return (
    <section>
      <Flex align="end" justify="space-between" wrap gap="middle" className="page-title-row">
        <div>
          <Typography.Title level={2}>任务中心</Typography.Title>
          <Typography.Text type="secondary">
            持久任务状态机、审批状态、实时事件和断点续跑记录。
          </Typography.Text>
        </div>
        <Input.Search
          allowClear
          aria-label="过滤任务"
          placeholder="按标题、目标或状态过滤"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          className="task-search"
        />
      </Flex>
      <Card>
        {query.isPending ? <LoadingState /> : null}
        {query.isError ? <QueryErrorState error={query.error} onRetry={() => void query.refetch()} /> : null}
        {query.isSuccess ? <TaskVirtualList tasks={filtered} /> : null}
      </Card>
    </section>
  );
}
