import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Card, Descriptions, List, Space, Tag, Typography } from 'antd';
import { lazy, Suspense, useState } from 'react';

import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { systemRequirementsQuery } from '../api/queries';

const MonacoEditor = lazy(() => import('@monaco-editor/react'));

export function SystemPage() {
  const query = useQuery(systemRequirementsQuery());
  const [showRaw, setShowRaw] = useState(false);

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>系统状态</Typography.Title>
        <Typography.Text type="secondary">运行能力、迁移状态和明确排除项。</Typography.Text>
      </div>
      {query.isPending ? <LoadingState /> : null}
      {query.isError ? <QueryErrorState error={query.error} onRetry={() => void query.refetch()} /> : null}
      {query.isSuccess ? (
        <Space direction="vertical" size="large" className="full-width">
          <Alert
            showIcon
            type={query.data.p0_migration.legacy_execution_enabled ? 'warning' : 'success'}
            message={`迁移状态：${query.data.p0_migration.status}`}
            description={query.data.p0_migration.compatibility}
          />
          <Card title="迁移边界">
            <Descriptions column={{ xs: 1, md: 2 }}>
              <Descriptions.Item label="目标">{query.data.p0_migration.target}</Descriptions.Item>
              <Descriptions.Item label="旧执行能力">
                <Tag color={query.data.p0_migration.legacy_execution_enabled ? 'red' : 'green'}>
                  {query.data.p0_migration.legacy_execution_enabled ? '已启用' : '默认关闭'}
                </Tag>
              </Descriptions.Item>
            </Descriptions>
          </Card>
          <Card title="本阶段排除项">
            <List dataSource={query.data.excluded} renderItem={(item) => <List.Item>{item}</List.Item>} />
          </Card>
          <Card title="契约响应">
            <Button onClick={() => setShowRaw((current) => !current)}>
              {showRaw ? '隐藏原始数据' : '按需加载 JSON 查看器'}
            </Button>
            {showRaw ? (
              <Suspense fallback={<LoadingState label="正在加载编辑器…" />}>
                <MonacoEditor
                  height="420px"
                  language="json"
                  value={JSON.stringify(query.data, null, 2)}
                  options={{ readOnly: true, minimap: { enabled: false }, automaticLayout: true }}
                />
              </Suspense>
            ) : null}
          </Card>
        </Space>
      ) : null}
    </section>
  );
}
