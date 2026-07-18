import { useMutation, useQuery } from '@tanstack/react-query';
import { Link, useParams } from '@tanstack/react-router';
import type {
  CaseDispositionCreate,
  CaseFinding,
  CaseFindingCreate,
  RemediationDecision,
  RemediationProposal,
  RemediationProposalCreate,
  RetestRequest,
  VulnerabilityCase,
} from '@vulnlab/shared-types';
import {
  App,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd';

import { queryClient } from '../../../app/query-client';
import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import {
  closeVulnerabilityCase,
  createCaseDisposition,
  createCaseFinding,
  createRemediationImplementation,
  createRemediationProposal,
  createRetestRequest,
  decideRemediationProposal,
  generateCaseReport,
  getRetestComparison,
  getVulnerabilityCaseDetail,
  updateVulnerabilityCase,
} from '../../../services/cases';

const CASE_STATUSES = [
  'DRAFT',
  'TRIAGE',
  'VALIDATION_PENDING',
  'VALIDATED',
  'REMEDIATION_PLANNED',
  'REMEDIATION_IN_PROGRESS',
  'RETEST_PENDING',
  'REMEDIATED',
  'ACCEPTED_RISK',
  'FALSE_POSITIVE',
  'INCONCLUSIVE',
  'CLOSED',
] as const;

interface TransitionFormValue {
  status: typeof CASE_STATUSES[number];
}

interface RetestFormValue {
  finding_id: string;
  original_execution_id: string;
  remediation_implementation_id: string;
}

function tagColor(value: string) {
  if (value === 'REMEDIATED' || value === 'APPROVED') return 'green';
  if (value === 'CLOSED') return 'default';
  if (value.includes('REMEDIATION') || value === 'QUEUED') return 'blue';
  if (value === 'REJECTED' || value === 'REGRESSION') return 'red';
  return 'geekblue';
}

export function CaseDetailPage() {
  const { caseId } = useParams({ from: '/cases/$caseId' });
  const { message } = App.useApp();
  const detail = useQuery({
    queryKey: ['vulnerability-case', caseId],
    queryFn: () => getVulnerabilityCaseDetail(caseId),
  });
  const invalidate = async () => {
    await queryClient.invalidateQueries({ queryKey: ['vulnerability-case', caseId] });
    await queryClient.invalidateQueries({ queryKey: ['vulnerability-cases'] });
  };
  const transition = useMutation({
    mutationFn: (value: TransitionFormValue) => updateVulnerabilityCase(caseId, {
      expected_version: detail.data?.case.version ?? 1,
      status: value.status,
    }),
    onSuccess: async () => {
      await invalidate();
      message.success('Case status updated.');
    },
  });
  const finding = useMutation({
    mutationFn: (value: CaseFindingCreate) => createCaseFinding(caseId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('Finding saved.');
    },
  });
  const proposal = useMutation({
    mutationFn: (value: RemediationProposalCreate) => createRemediationProposal(caseId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('Proposal saved.');
    },
  });
  const decision = useMutation({
    mutationFn: ({ id, decision: value }: { decision: RemediationDecision['decision']; id: string }) => decideRemediationProposal(id, {
      decision: value,
      reason: `Human decision from case console: ${value}`,
      automated: false,
    }),
    onSuccess: async () => {
      await invalidate();
      message.success('Decision saved.');
    },
  });
  const implementation = useMutation({
    mutationFn: (id: string) => createRemediationImplementation(id, {
      implementation_ref: `case-console://${caseId}/${Date.now()}`,
      description: 'Implementation record entered from case console.',
      verification_notes: 'Ready for P9 retest.',
    }),
    onSuccess: async () => {
      await invalidate();
      message.success('Implementation recorded.');
    },
  });
  const retest = useMutation({
    mutationFn: (value: RetestFormValue) => createRetestRequest(caseId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('Retest queued.');
    },
  });
  const comparison = useMutation({
    mutationFn: getRetestComparison,
    onSuccess: async () => {
      await invalidate();
      message.success('Comparison generated.');
    },
  });
  const disposition = useMutation({
    mutationFn: (value: CaseDispositionCreate) => createCaseDisposition(caseId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('Disposition recorded.');
    },
  });
  const report = useMutation({
    mutationFn: () => generateCaseReport(caseId, { title: `Case report ${caseId.slice(0, 8)}` }),
    onSuccess: async () => {
      await invalidate();
      message.success('Report generated.');
    },
  });
  const closeCase = useMutation({
    mutationFn: () => closeVulnerabilityCase(caseId, {
      expected_version: detail.data?.case.version ?? 1,
      reason: 'Closed from case console',
    }),
    onSuccess: async () => {
      await invalidate();
      message.success('Case closed.');
    },
  });
  const firstError = detail.error
    ?? transition.error
    ?? finding.error
    ?? proposal.error
    ?? decision.error
    ?? implementation.error
    ?? retest.error
    ?? comparison.error
    ?? disposition.error
    ?? report.error
    ?? closeCase.error;

  if (detail.isPending) return <LoadingState />;
  if (detail.isError) return <QueryErrorState error={detail.error} onRetry={() => void detail.refetch()} />;

  const data = detail.data;
  const currentCase = data.case;
  const validatedFindings = data.findings.filter((item) => item.status === 'VALIDATED');
  const approvedDecisions = data.remediation_decisions.filter((item) => item.decision === 'APPROVED');
  const findingOptions = data.findings.map((item) => ({ value: item.id, label: item.title }));
  const originalExecutionOptions = data.findings
    .filter((item) => item.validation_execution_id)
    .map((item) => ({ value: item.validation_execution_id ?? '', label: `${item.title} / ${item.validation_execution_id}` }));
  const implementationOptions = data.remediation_implementations.map((item) => ({
    value: item.id,
    label: item.implementation_ref,
  }));

  return (
    <section>
      <div className="page-title-row">
        <Space direction="vertical">
          <Link to="/cases"><Button>Back to cases</Button></Link>
          <Typography.Title level={2}>{currentCase.title}</Typography.Title>
          <Space>
            <Tag color={tagColor(currentCase.status)}>{currentCase.status}</Tag>
            <Tag>{currentCase.severity}</Tag>
            <Typography.Text type="secondary">version {currentCase.version}</Typography.Text>
          </Space>
        </Space>
      </div>
      {firstError ? <QueryErrorState error={firstError} onRetry={() => {
        transition.reset();
        finding.reset();
        proposal.reset();
        decision.reset();
        implementation.reset();
        retest.reset();
        comparison.reset();
        disposition.reset();
        report.reset();
        closeCase.reset();
        void detail.refetch();
      }} /> : null}
      <Card title="Overview">
        <Descriptions column={2} bordered size="small">
          <Descriptions.Item label="Case ID">{currentCase.id}</Descriptions.Item>
          <Descriptions.Item label="Project">{currentCase.project_id}</Descriptions.Item>
          <Descriptions.Item label="Tenant">{currentCase.tenant_id}</Descriptions.Item>
          <Descriptions.Item label="Source">{currentCase.source}</Descriptions.Item>
          <Descriptions.Item label="Summary" span={2}>{currentCase.summary}</Descriptions.Item>
          <Descriptions.Item label="Created">{currentCase.created_at}</Descriptions.Item>
          <Descriptions.Item label="Updated">{currentCase.updated_at}</Descriptions.Item>
        </Descriptions>
      </Card>
      <Card title="Human workflow controls" className="section-gap">
        <Space direction="vertical" className="full-width">
          <Form<TransitionFormValue>
            layout="inline"
            initialValues={{ status: currentCase.status }}
            onFinish={(value) => transition.mutate(value)}
          >
            <Form.Item name="status" label="Next state">
              <Select options={CASE_STATUSES.map((value) => ({ value, label: value }))} className="wide-select" />
            </Form.Item>
            <Form.Item>
              <Button htmlType="submit" loading={transition.isPending}>Transition</Button>
            </Form.Item>
          </Form>
          <Space wrap>
            <Button loading={report.isPending} onClick={() => report.mutate()}>Generate report</Button>
            <Button danger loading={closeCase.isPending} disabled={currentCase.status === 'CLOSED'} onClick={() => closeCase.mutate()}>Close case</Button>
          </Space>
        </Space>
      </Card>
      <Tabs
        className="section-gap"
        items={[
          {
            key: 'findings',
            label: `Findings (${data.findings.length})`,
            children: (
              <Space direction="vertical" className="full-width">
                <Form<CaseFindingCreate>
                  layout="vertical"
                  initialValues={{ risk_level: currentCase.severity, status: 'CANDIDATE' }}
                  onFinish={(value) => finding.mutate(value)}
                >
                  <Space wrap align="start">
                    <Form.Item name="title" label="Title" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name="description" label="Description" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name="validation_execution_id" label="Validation execution"><Input /></Form.Item>
                    <Form.Item name="evidence_id" label="Evidence ID"><Input /></Form.Item>
                    <Form.Item name="status" label="Status"><Select options={['CANDIDATE', 'VALIDATED', 'FALSE_POSITIVE', 'INCONCLUSIVE'].map((value) => ({ value, label: value }))} /></Form.Item>
                    <Form.Item name="risk_level" label="Risk"><Select options={['informational', 'low', 'medium', 'high', 'critical'].map((value) => ({ value, label: value }))} /></Form.Item>
                    <Form.Item label=" "><Button htmlType="submit" loading={finding.isPending}>Add finding</Button></Form.Item>
                  </Space>
                </Form>
                <Table<CaseFinding>
                  size="small"
                  rowKey="id"
                  dataSource={data.findings}
                  columns={[
                    { title: 'Title', dataIndex: 'title' },
                    { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag color={tagColor(value)}>{value}</Tag> },
                    { title: 'Execution', dataIndex: 'validation_execution_id', ellipsis: true },
                    { title: 'Evidence', dataIndex: 'evidence_id', ellipsis: true },
                    { title: 'Risk', dataIndex: 'risk_level' },
                  ]}
                />
              </Space>
            ),
          },
          {
            key: 'remediation',
            label: 'Remediation',
            children: (
              <Space direction="vertical" className="full-width">
                <Form<RemediationProposalCreate>
                  layout="vertical"
                  initialValues={{ source: 'MANUAL', risk_level: 'medium' }}
                  onFinish={(value) => proposal.mutate({ ...value, knowledge_refs: value.knowledge_refs ?? [], provenance: value.provenance ?? {} })}
                >
                  <Space wrap align="start">
                    <Form.Item name="source" label="Source"><Select options={['AI_GENERATED', 'KNOWLEDGE_BASE', 'VENDOR_ADVISORY', 'MANUAL'].map((value) => ({ value, label: value }))} /></Form.Item>
                    <Form.Item name="title" label="Title" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name="description" label="Description" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name="risk_level" label="Risk"><Select options={['low', 'medium', 'high'].map((value) => ({ value, label: value }))} /></Form.Item>
                    <Form.Item label=" "><Button htmlType="submit" loading={proposal.isPending}>Add proposal</Button></Form.Item>
                  </Space>
                </Form>
                <Table<RemediationProposal>
                  size="small"
                  rowKey="id"
                  dataSource={data.remediation_proposals}
                  columns={[
                    { title: 'Title', dataIndex: 'title' },
                    { title: 'Source', dataIndex: 'source' },
                    { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag color={tagColor(value)}>{value}</Tag> },
                    { title: 'Risk', dataIndex: 'risk_level' },
                    {
                      title: 'Human decision',
                      render: (_: unknown, record) => (
                        <Space>
                          <Button size="small" loading={decision.isPending} onClick={() => decision.mutate({ id: record.id, decision: 'APPROVED' })}>Approve</Button>
                          <Button size="small" danger loading={decision.isPending} onClick={() => decision.mutate({ id: record.id, decision: 'REJECTED' })}>Reject</Button>
                        </Space>
                      ),
                    },
                  ]}
                />
                <Table<RemediationDecision>
                  size="small"
                  rowKey="id"
                  dataSource={data.remediation_decisions}
                  columns={[
                    { title: 'Decision', dataIndex: 'decision', render: (value: string) => <Tag color={tagColor(value)}>{value}</Tag> },
                    { title: 'Reason', dataIndex: 'reason' },
                    { title: 'By', dataIndex: 'decided_by' },
                    {
                      title: 'Implementation',
                      render: (_: unknown, record) => (
                        <Button size="small" disabled={record.decision !== 'APPROVED'} loading={implementation.isPending} onClick={() => implementation.mutate(record.id)}>Record implementation</Button>
                      ),
                    },
                  ]}
                />
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.remediation_implementations}
                  columns={[
                    { title: 'Implementation ref', dataIndex: 'implementation_ref' },
                    { title: 'Description', dataIndex: 'description' },
                    { title: 'Implemented by', dataIndex: 'implemented_by' },
                    { title: 'Implemented at', dataIndex: 'implemented_at' },
                  ]}
                />
              </Space>
            ),
          },
          {
            key: 'retest',
            label: 'Retest and comparison',
            children: (
              <Space direction="vertical" className="full-width">
                <Form<RetestFormValue>
                  layout="inline"
                  disabled={!validatedFindings.length || !approvedDecisions.length}
                  onFinish={(value) => retest.mutate(value)}
                >
                  <Form.Item name="finding_id" label="Finding" rules={[{ required: true }]}><Select options={findingOptions} className="wide-select" /></Form.Item>
                  <Form.Item name="original_execution_id" label="Original execution" rules={[{ required: true }]}><Select options={originalExecutionOptions} className="wide-select" /></Form.Item>
                  <Form.Item name="remediation_implementation_id" label="Implementation" rules={[{ required: true }]}><Select options={implementationOptions} className="wide-select" /></Form.Item>
                  <Form.Item><Button htmlType="submit" loading={retest.isPending}>Queue retest</Button></Form.Item>
                </Form>
                <Table<RetestRequest>
                  size="small"
                  rowKey="id"
                  dataSource={data.retests}
                  columns={[
                    { title: 'Status', dataIndex: 'status', render: (value: string) => <Tag color={tagColor(value)}>{value}</Tag> },
                    { title: 'Original', dataIndex: 'original_execution_id', ellipsis: true },
                    { title: 'Retest execution', dataIndex: 'retest_execution_id', ellipsis: true },
                    { title: 'Template', dataIndex: 'template_id' },
                    {
                      title: 'Comparison',
                      render: (_: unknown, record) => (
                        <Button size="small" loading={comparison.isPending} onClick={() => comparison.mutate(record.id)}>Generate comparison</Button>
                      ),
                    },
                  ]}
                />
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.comparisons}
                  columns={[
                    { title: 'Result', dataIndex: 'result', render: (value: string) => <Tag color={tagColor(value)}>{value}</Tag> },
                    { title: 'Initial', dataIndex: 'initial_status' },
                    { title: 'Retest', dataIndex: 'retest_status' },
                    { title: 'Residual risk', dataIndex: 'residual_risk' },
                    { title: 'Recommendation', dataIndex: 'recommendation' },
                  ]}
                />
                <Form<CaseDispositionCreate>
                  layout="inline"
                  initialValues={{ disposition: 'INCONCLUSIVE', human_confirmed: true }}
                  onFinish={(value) => disposition.mutate({
                    ...value,
                    expected_version: currentCase.version,
                    human_confirmed: true,
                  })}
                >
                  <Form.Item name="disposition" label="Disposition"><Select options={['REMEDIATED', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'INCONCLUSIVE'].map((value) => ({ value, label: value }))} /></Form.Item>
                  <Form.Item name="reason" label="Reason" rules={[{ required: true }]}><Input /></Form.Item>
                  <Form.Item name="residual_risk" label="Residual risk"><Input /></Form.Item>
                  <Form.Item><Button htmlType="submit" loading={disposition.isPending}>Human confirm</Button></Form.Item>
                </Form>
              </Space>
            ),
          },
          {
            key: 'reports',
            label: 'Reports and audit',
            children: (
              <Space direction="vertical" className="full-width">
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.dispositions}
                  columns={[
                    { title: 'Disposition', dataIndex: 'disposition', render: (value: string) => <Tag color={tagColor(value)}>{value}</Tag> },
                    { title: 'Reason', dataIndex: 'reason' },
                    { title: 'Human confirmed', dataIndex: 'human_confirmed', render: (value: boolean) => String(value) },
                  ]}
                />
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.reports}
                  columns={[
                    { title: 'Title', dataIndex: 'title' },
                    { title: 'Generated by', dataIndex: 'generated_by' },
                    { title: 'Generated at', dataIndex: 'generated_at' },
                  ]}
                />
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.audit_events}
                  columns={[
                    { title: 'Action', dataIndex: 'action' },
                    { title: 'Actor', dataIndex: 'actor_id' },
                    { title: 'Resource', dataIndex: 'resource_id', ellipsis: true },
                    { title: 'Time', dataIndex: 'timestamp' },
                  ]}
                />
              </Space>
            ),
          },
        ]}
      />
    </section>
  );
}
