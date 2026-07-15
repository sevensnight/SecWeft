import { Link } from '@tanstack/react-router';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { Task } from '@vulnlab/shared-types';
import { StatusPill } from '@vulnlab/ui-components';
import { Button, Flex, Typography } from 'antd';
import { useRef } from 'react';

import { EmptyState } from '../../../components/EmptyState';

export function TaskVirtualList({ tasks }: { tasks: Task[] }) {
  const parentRef = useRef<HTMLDivElement>(null);
  // React Compiler cannot memoize TanStack Virtual's imperative callbacks; the component remains correct.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: tasks.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 76,
    overscan: 8,
  });

  if (tasks.length === 0) return <EmptyState description="没有符合条件的任务" />;

  return (
    <div ref={parentRef} className="virtual-list" role="list" aria-label="任务列表">
      <div className="virtual-list-inner" style={{ height: virtualizer.getTotalSize() }}>
        {virtualizer.getVirtualItems().map((row) => {
          const task = tasks[row.index];
          if (!task) return null;
          return (
            <div
              key={task.id}
              role="listitem"
              className="task-row"
              style={{ transform: `translateY(${row.start}px)` }}
            >
              <Flex vertical gap={4} className="task-row-main">
                <Typography.Text strong ellipsis>{task.title}</Typography.Text>
                <Typography.Text type="secondary" ellipsis>{task.target}</Typography.Text>
              </Flex>
              <StatusPill status={task.status} />
              <Typography.Text className="task-row-date">
                {new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(task.updated_at))}
              </Typography.Text>
              <Link to="/tasks/$taskId" params={{ taskId: task.id }}><Button type="link">查看</Button></Link>
            </div>
          );
        })}
      </div>
    </div>
  );
}
