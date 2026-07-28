import { useQuery } from '@tanstack/react-query';
import { Card, Col, Row, Space, Statistic, Table, Tabs, Tag, Typography } from 'antd';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnBoolean, cnLabel } from '../../../i18n/formatters';
import { listAgents, listSkills, listWorkflows } from '../../../services/api';

export function AgentsPage() {
  const agents = useQuery({
    queryKey: ['agents'],
    queryFn: listAgents,
    staleTime: 30_000,
  });
  const workflows = useQuery({
    queryKey: ['workflows'],
    queryFn: listWorkflows,
    staleTime: 30_000,
  });
  const skills = useQuery({
    queryKey: ['skills'],
    queryFn: listSkills,
    staleTime: 30_000,
  });
  const isPending = agents.isPending || workflows.isPending || skills.isPending;
  const firstError = agents.error ?? workflows.error ?? skills.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>智能体与技能管理</Typography.Title>
        <Typography.Text type="secondary">
          展示已注册智能体、工作流和技能的职责、风险、预算与启用状态。
        </Typography.Text>
      </div>

      {isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        void agents.refetch();
        void workflows.refetch();
        void skills.refetch();
      }} /> : null}

      {!isPending && !firstError ? (
        <Space direction="vertical" size="large" className="full-width">
          <Row gutter={[16, 16]}>
            <Col xs={24} md={8}><Card><Statistic title="智能体" value={agents.data?.length ?? 0} /></Card></Col>
            <Col xs={24} md={8}><Card><Statistic title="工作流" value={workflows.data?.length ?? 0} /></Card></Col>
            <Col xs={24} md={8}><Card><Statistic title="技能" value={skills.data?.length ?? 0} /></Card></Col>
          </Row>

          <Tabs
            items={[
              {
                key: 'agents',
                label: '智能体',
                children: (
                  <Table
                    size="small"
                    rowKey="id"
                    dataSource={agents.data ?? []}
                    columns={[
                      { title: '名称', dataIndex: 'name' },
                      { title: '版本', dataIndex: 'version' },
                      { title: '风险', dataIndex: 'risk_level', render: (value) => <Tag>{cnLabel(value)}</Tag> },
                      { title: 'Token 预算', dataIndex: 'token_budget' },
                      { title: '超时秒数', dataIndex: 'timeout_seconds' },
                      {
                        title: '状态',
                        dataIndex: 'enabled',
                        render: (enabled) => <Tag color={enabled ? 'green' : 'default'}>{enabled ? '启用' : '停用'}</Tag>,
                      },
                    ]}
                  />
                ),
              },
              {
                key: 'workflows',
                label: '工作流',
                children: (
                  <Table
                    size="small"
                    rowKey="id"
                    dataSource={workflows.data ?? []}
                    columns={[
                      { title: '名称', dataIndex: 'name' },
                      { title: '版本', dataIndex: 'version' },
                      { title: '阶段数', dataIndex: 'stages', render: (values: unknown[]) => values.length },
                      {
                        title: '状态',
                        dataIndex: 'enabled',
                        render: (enabled) => <Tag color={enabled ? 'green' : 'default'}>{enabled ? '启用' : '停用'}</Tag>,
                      },
                    ]}
                  />
                ),
              },
              {
                key: 'skills',
                label: '技能',
                children: (
                  <Table
                    size="small"
                    rowKey="id"
                    dataSource={skills.data ?? []}
                    columns={[
                      { title: '名称', dataIndex: 'name' },
                      { title: '版本', dataIndex: 'version' },
                      { title: '执行器', dataIndex: 'executor_type', render: (value) => <Tag>{cnLabel(value)}</Tag> },
                      { title: '风险', dataIndex: 'risk_level', render: (value) => <Tag>{cnLabel(value)}</Tag> },
                      { title: '需要审批', dataIndex: 'approval_required', render: (value) => cnBoolean(Boolean(value)) },
                      {
                        title: '状态',
                        dataIndex: 'enabled',
                        render: (enabled) => <Tag color={enabled ? 'green' : 'default'}>{enabled ? '启用' : '停用'}</Tag>,
                      },
                    ]}
                  />
                ),
              },
            ]}
          />
        </Space>
      ) : null}
    </section>
  );
}
