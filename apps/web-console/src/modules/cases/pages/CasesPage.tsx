import { useMutation, useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { VulnerabilityCase, VulnerabilityCaseCreate } from '@vulnlab/shared-types';
import { App, Button, Card, Form, Input, Select, Space, Table, Tag, Typography } from 'antd';

import { queryClient } from '../../../app/query-client';
import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
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
      message.success('Case created.');
    },
  });
  const firstError = cases.error ?? createCase.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>Vulnerability Cases</Typography.Title>
        <Typography.Text type="secondary">
          Track findings from validation through remediation decision, retest comparison, report, and closure.
        </Typography.Text>
      </div>
      {cases.isPending ? <LoadingState /> : null}
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        createCase.reset();
        void cases.refetch();
      }} /> : null}
      <Card title="Create case">
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
            <Form.Item name="title" label="Title" rules={[{ required: true }]}>
              <Input className="wide-input" />
            </Form.Item>
            <Form.Item name="summary" label="Summary" rules={[{ required: true }]}>
              <Input className="wide-input" />
            </Form.Item>
            <Form.Item name="severity" label="Severity" rules={[{ required: true }]}>
              <Select
                className="compact-select"
                options={['informational', 'low', 'medium', 'high', 'critical'].map((value) => ({ value, label: value }))}
              />
            </Form.Item>
            <Form.Item name="project_id" label="Project">
              <Input />
            </Form.Item>
            <Form.Item label=" ">
              <Button type="primary" htmlType="submit" loading={createCase.isPending}>Create</Button>
            </Form.Item>
          </Space>
        </Form>
      </Card>
      <Card title="Cases" className="section-gap" loading={cases.isPending}>
        <Table<VulnerabilityCase>
          size="small"
          rowKey="id"
          dataSource={cases.data ?? []}
          columns={[
            {
              title: 'Case',
              dataIndex: 'title',
              render: (value: string, record) => <Link to="/cases/$caseId" params={{ caseId: record.id }}>{value}</Link>,
            },
            { title: 'Severity', dataIndex: 'severity', render: (value: string) => <Tag>{value}</Tag> },
            { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag color={caseStatusColor(value)}>{value}</Tag> },
            { title: 'Project', dataIndex: 'project_id' },
            { title: 'Version', dataIndex: 'version' },
            { title: 'Updated', dataIndex: 'updated_at' },
          ]}
        />
      </Card>
    </section>
  );
}
