import { useMutation, useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { VulnerabilityCase, VulnerabilityCaseCreate } from '@vulnlab/shared-types';
import { App, Button, Card, Form, Input, Select, Space, Table, Tag, Typography } from 'antd';

import { queryClient } from '../../../app/query-client';
import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnLabel } from '../../../i18n/formatters';
import { createVulnerabilityCase, listVulnerabilityCases } from '../../../services/cases';

interface CaseFormValue {
  project_id?: string;
  severity: VulnerabilityCaseCreate['severity'];
  summary: string;
  title: string;
}

function caseStatusColor(status: string) {
  if (status === 'CLOSED') return 'default';
  if (status === 'REMEDIATED') return 'green';
  if (['FALSE_POSITIVE', 'ACCEPTED_RISK', 'INCONCLUSIVE'].includes(status)) return 'orange';
  if (status.includes('REMEDIATION')) return 'blue';
  return 'geekblue';
}

export function CasesPage() {
  const { message } = App.useApp();
  const cases = useQuery({
    queryKey: ['vulnerability-cases'],
    queryFn: () => listVulnerabilityCases(200),
  });
  const createCase = useMutation({
    mutationFn: (value: VulnerabilityCaseCreate) => createVulnerabilityCase(value),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['vulnerability-cases'] });
      message.success('案件已创建。');
    },
  });
  const firstError = cases.error ?? createCase.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>漏洞案件</Typography.Title>
        <Typography.Text type="secondary">
          跟踪发现项从验证、修复决策、复测对比、报告生成到关闭的完整流程。
        </Typography.Text>
      </div>
      {cases.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        createCase.reset();
        void cases.refetch();
      }} /> : null}
      <Card title="创建案件">
        <Form<CaseFormValue>
          layout="vertical"
          initialValues={{ project_id: 'project-alpha', severity: 'medium' }}
          onFinish={(value) => createCase.mutate({
            title: value.title,
            summary: value.summary,
            severity: value.severity,
            project_id: value.project_id || 'project-alpha',
            source: 'MANUAL',
            metadata: { created_from: 'web-console' },
          })}
        >
          <Space wrap align="start">
            <Form.Item name="title" label="标题" rules={[{ required: true }]}>
              <Input className="wide-input" />
            </Form.Item>
            <Form.Item name="summary" label="摘要" rules={[{ required: true }]}>
              <Input className="wide-input" />
            </Form.Item>
            <Form.Item name="severity" label="严重程度" rules={[{ required: true }]}>
              <Select
                className="compact-select"
                options={['informational', 'low', 'medium', 'high', 'critical'].map((value) => ({ value, label: cnLabel(value) }))}
              />
            </Form.Item>
            <Form.Item name="project_id" label="项目">
              <Input />
            </Form.Item>
            <Form.Item label=" ">
              <Button type="primary" htmlType="submit" loading={createCase.isPending}>创建</Button>
            </Form.Item>
          </Space>
        </Form>
      </Card>
      <Card title="案件列表" className="section-gap" loading={cases.isPending}>
        <Table<VulnerabilityCase>
          size="small"
          rowKey="id"
          dataSource={cases.data ?? []}
          columns={[
            {
              title: '案件',
              dataIndex: 'title',
              render: (value: string, record) => <Link to="/cases/$caseId" params={{ caseId: record.id }}>{value}</Link>,
            },
            { title: '严重程度', dataIndex: 'severity', render: (value: string) => <Tag>{cnLabel(value)}</Tag> },
            { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={caseStatusColor(value)}>{cnLabel(value)}</Tag> },
            { title: '项目', dataIndex: 'project_id' },
            { title: '版本', dataIndex: 'version' },
            { title: '更新时间', dataIndex: 'updated_at' },
          ]}
        />
      </Card>
    </section>
  );
}
