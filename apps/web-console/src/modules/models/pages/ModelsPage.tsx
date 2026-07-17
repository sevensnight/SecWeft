import { useQuery } from '@tanstack/react-query';
import type { ModelCatalogItem, ModelInvocation, ModelProvider } from '@vulnlab/shared-types';
import { Alert, Card, Col, Row, Space, Statistic, Table, Tag, Typography } from 'antd';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
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
        <Typography.Title level={2}>Model Management</Typography.Title>
        <Typography.Text type="secondary">
          Provider inventory, health, routable catalog, and invocation audit from the generated API client.
        </Typography.Text>
      </div>
      <Alert
        showIcon
        type="info"
        message="Credentials are backend-owned"
        description="The console never renders or persists plaintext model credentials."
        className="section-gap"
      />
      {isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        void providers.refetch();
        void health.refetch();
        void catalog.refetch();
        void invocations.refetch();
      }} /> : null}
      {!isPending && !firstError ? (
        <Space direction="vertical" size="large" className="full-width">
          <Row gutter={[16, 16]}>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="Providers" value={providers.data?.length ?? 0} /></Card></Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="Models" value={catalog.data?.length ?? 0} /></Card></Col>
            <Col xs={24} sm={12} lg={6}>
              <Card><Statistic title="Ready providers" value={(health.data ?? []).filter((item) => item.status === 'ready').length} /></Card>
            </Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="Recent calls" value={invocations.data?.length ?? 0} /></Card></Col>
          </Row>
          <Card title="Providers">
            <Table<ModelProvider>
              size="small"
              rowKey="id"
              pagination={{ pageSize: 8 }}
              dataSource={providers.data ?? []}
              columns={[
                { title: 'Name', dataIndex: 'name' },
                { title: 'Kind', dataIndex: 'kind', render: (value: string) => <Tag>{value}</Tag> },
                { title: 'Enabled', dataIndex: 'enabled', render: (value: boolean) => <Tag color={value ? 'green' : 'default'}>{value ? 'enabled' : 'disabled'}</Tag> },
                { title: 'Base URL', dataIndex: 'base_url', ellipsis: true },
                { title: 'Updated', dataIndex: 'updated_at' },
              ]}
            />
          </Card>
          <Card title="Catalog">
            <Table<ModelCatalogItem>
              size="small"
              rowKey={(item) => `${item.provider_id}:${item.model}`}
              pagination={{ pageSize: 8 }}
              dataSource={catalog.data ?? []}
              columns={[
                { title: 'Provider', dataIndex: 'provider' },
                { title: 'Model', dataIndex: 'model' },
                { title: 'Context', dataIndex: 'context_window' },
                { title: 'Capabilities', dataIndex: 'capabilities', render: (values: string[]) => <Space wrap>{values.map((value) => <Tag key={value}>{value}</Tag>)}</Space> },
              ]}
            />
          </Card>
          <Card title="Invocations">
            <Table<ModelInvocation>
              size="small"
              rowKey="id"
              pagination={{ pageSize: 8 }}
              dataSource={invocations.data ?? []}
              columns={[
                { title: 'Provider', dataIndex: 'provider' },
                { title: 'Model', dataIndex: 'model' },
                { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag>{value}</Tag> },
                { title: 'Tokens', dataIndex: 'total_tokens' },
                { title: 'Cost', dataIndex: 'cost_estimate' },
                { title: 'Created', dataIndex: 'created_at' },
              ]}
            />
          </Card>
        </Space>
      ) : null}
    </section>
  );
}
