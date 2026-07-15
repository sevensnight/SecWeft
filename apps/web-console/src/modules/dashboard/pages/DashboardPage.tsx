import { useQuery } from '@tanstack/react-query';
import { Alert, Card, Col, Row, Statistic, Typography } from 'antd';
import { lazy, Suspense } from 'react';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { tasksQuery } from '../../tasks/api/queries';
import { countTaskStatuses } from '../../tasks/utils/task-status';

const TaskStatusChart = lazy(() => import('../components/TaskStatusChart').then((module) => ({
  default: module.TaskStatusChart,
})));

export function DashboardPage() {
  const query = useQuery(tasksQuery());
  const tasks = query.data ?? [];
  const statusCounts = countTaskStatuses(tasks);

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>综合态势</Typography.Title>
        <Typography.Text type="secondary">面向 P0 工程基线的只读运行视图</Typography.Text>
      </div>
      <Alert
        showIcon
        type="info"
        message="P0 安全模式已启用"
        description="资产探测、沙箱运行和旧任务执行默认关闭；本页只展示兼容投影。"
        className="section-gap"
      />
      {query.isPending ? <LoadingState /> : null}
      {query.isError ? <QueryErrorState error={query.error} onRetry={() => void query.refetch()} /> : null}
      {query.isSuccess ? (
        <>
          <Row gutter={[16, 16]}>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="任务总数" value={tasks.length} /></Card></Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="运行中" value={statusCounts.running ?? 0} /></Card></Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="已成功" value={statusCounts.succeeded ?? 0} /></Card></Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="待审批" value={statusCounts.pending_approval ?? 0} /></Card></Col>
          </Row>
          <Card title="任务状态分布" className="section-gap">
            <Suspense fallback={<LoadingState label="正在加载图表…" />}>
              <TaskStatusChart values={statusCounts} />
            </Suspense>
          </Card>
        </>
      ) : null}
    </section>
  );
}
