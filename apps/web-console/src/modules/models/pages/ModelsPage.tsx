import { useQuery } from '@tanstack/react-query';
import type { ModelCatalogItem, ModelInvocation, ModelProvider } from '@vulnlab/shared-types';
import { Alert, Card, Col, Row, Space, Statistic, Table, Tag, Typography } from 'antd';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnLabel } from '../../../i18n/formatters';
import {
  listModelCatalog,
  listModelInvocations,
  listModelProviderHealth,
  listModelProviders,
} from '../../../services/api';

export function ModelsPage() {
  const providers = useQuery({ queryKey: ['models', 'providers'], queryFn: listModelProviders, staleTime: 15_000 });
  const health = useQuery({ queryKey: ['models', 'health'], queryFn: listModelProviderHealth, staleTime: 10_000 });
  const catalog = useQuery({ queryKey: ['models', 'catalog'], queryFn: listModelCatalog, staleTime: 30_000 });
  const invocations = useQuery({
    queryKey: ['models', 'invocations'],
    queryFn: () => listModelInvocations(100),
    staleTime: 10_000,
  });
  const isPending = providers.isPending || health.isPending || catalog.isPending || invocations.isPending;
  const firstError = providers.error ?? health.error ?? catalog.error ?? invocations.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>模型管理</Typography.Title>
        <Typography.Text type="secondary">
          基于生成的 API 客户端查看供应商清单、健康状态、可路由模型目录和调用审计。
        </Typography.Text>
      </div>
      <Alert
        showIcon
        type="info"
        message="凭据由后端托管"
        description="控制台不会展示或持久化模型明文凭据。"
      />
      {isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        void providers.refetch();
        void health.refetch();
        void catalog.refetch();
        void invocations.refetch();
      }} /> : null}
      {!isPending && !firstError ? (
        <Space direction="vertical" size="middle" className="full-width section-gap">
          <Row gutter={[16, 16]}>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="供应商" value={providers.data?.length ?? 0} /></Card></Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="模型" value={catalog.data?.length ?? 0} /></Card></Col>
            <Col xs={24} sm={12} lg={6}>
              <Card><Statistic title="就绪供应商" value={(health.data ?? []).filter((item) => item.status === 'ready').length} /></Card>
            </Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="最近调用" value={invocations.data?.length ?? 0} /></Card></Col>
          </Row>
          <Card title="供应商">
            <Table<ModelProvider>
              size="small"
              rowKey="id"
              pagination={{ pageSize: 8 }}
              dataSource={providers.data ?? []}
              columns={[
                { title: '名称', dataIndex: 'name' },
                { title: '类型', dataIndex: 'kind', render: (value: string) => <Tag>{cnLabel(value)}</Tag> },
                { title: '启用状态', dataIndex: 'enabled', render: (value: boolean) => <Tag color={value ? 'green' : 'default'}>{value ? '启用' : '停用'}</Tag> },
                { title: '基础地址', dataIndex: 'base_url', ellipsis: true },
                { title: '更新时间', dataIndex: 'updated_at' },
              ]}
            />
          </Card>
          <Card title="模型目录">
            <Table<ModelCatalogItem>
              size="small"
              rowKey={(item) => `${item.provider_id}:${item.model}`}
              pagination={{ pageSize: 8 }}
              dataSource={catalog.data ?? []}
              columns={[
                { title: '供应商', dataIndex: 'provider' },
                { title: '模型', dataIndex: 'model' },
                { title: '上下文窗口', dataIndex: 'context_window' },
                { title: '能力', dataIndex: 'capabilities', render: (values: string[]) => <Space wrap>{values.map((value) => <Tag key={value}>{cnLabel(value)}</Tag>)}</Space> },
              ]}
            />
          </Card>
          <Card title="调用记录">
            <Table<ModelInvocation>
              size="small"
              rowKey="id"
              pagination={{ pageSize: 8 }}
              dataSource={invocations.data ?? []}
              columns={[
                { title: '供应商', dataIndex: 'provider' },
                { title: '模型', dataIndex: 'model' },
                { title: '状态', dataIndex: 'status', render: (value: string) => <Tag>{cnLabel(value)}</Tag> },
                { title: 'Token 数', dataIndex: 'total_tokens' },
                { title: '成本估算', dataIndex: 'cost_estimate' },
                { title: '创建时间', dataIndex: 'created_at' },
              ]}
            />
          </Card>
        </Space>
      ) : null}
    </section>
  );
}
