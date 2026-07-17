import { useQuery } from '@tanstack/react-query';
import { Alert, Card, Col, Row, Statistic, Table, Tag, Typography } from 'antd';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { getSystemRequirements, listTasks } from '../../../services/api';

export function AssetsPage() {
  const tasks = useQuery({ queryKey: ['tasks'], queryFn: () => listTasks() });
  const system = useQuery({ queryKey: ['system', 'requirements'], queryFn: getSystemRequirements });
  const scopes = new Set((tasks.data ?? []).map((task) => task.scope_id).filter(Boolean));
  const firstError = tasks.error ?? system.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>授权资产</Typography.Title>
        <Typography.Text type="secondary">
          当前前端只展示已进入任务账本的授权目标和 scope 绑定，不暴露兼容资产探测入口。
        </Typography.Text>
      </div>

      <Alert
        showIcon
        type="success"
        message="默认不连接互联网真实目标"
        description="资产探测、端口访问和验证步骤必须经过 Scope、Policy、审批和审计；未在契约中开放的执行能力不会在前端伪造。"
      />

      {tasks.isPending || system.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        void tasks.refetch();
        void system.refetch();
      }} /> : null}

      {!tasks.isPending && !system.isPending && !firstError ? (
        <>
          <Row gutter={[16, 16]} className="section-gap">
            <Col xs={24} md={8}><Card><Statistic title="任务目标" value={tasks.data?.length ?? 0} /></Card></Col>
            <Col xs={24} md={8}><Card><Statistic title="Scope 绑定" value={scopes.size} /></Card></Col>
            <Col xs={24} md={8}><Card><Statistic title="排除能力" value={system.data?.excluded.length ?? 0} /></Card></Col>
          </Row>

          <Card title="任务授权目标" className="section-gap">
            <Table
              size="small"
              rowKey="id"
              dataSource={tasks.data ?? []}
              columns={[
                { title: '任务', dataIndex: 'title' },
                { title: '目标', dataIndex: 'target', ellipsis: true },
                { title: 'Scope', dataIndex: 'scope_id', ellipsis: true },
                { title: '审批', dataIndex: 'approval_status', render: (value: string) => <Tag>{value}</Tag> },
                { title: '状态', dataIndex: 'status', render: (value: string) => <Tag>{value}</Tag> },
              ]}
            />
          </Card>

          <Card title="系统排除项" className="section-gap">
            <Table
              size="small"
              rowKey={(value) => value}
              dataSource={system.data?.excluded ?? []}
              columns={[{ title: '未开放能力', render: (value: string) => value }]}
              pagination={false}
            />
          </Card>
        </>
      ) : null}
    </section>
  );
}
