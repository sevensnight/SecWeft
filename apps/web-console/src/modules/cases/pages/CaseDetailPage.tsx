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
import { cnBoolean, cnLabel } from '../../../i18n/formatters';
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
      message.success('案件状态已更新。');
    },
  });
  const finding = useMutation({
    mutationFn: (value: CaseFindingCreate) => createCaseFinding(caseId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('发现项已保存。');
    },
  });
  const proposal = useMutation({
    mutationFn: (value: RemediationProposalCreate) => createRemediationProposal(caseId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('修复建议已保存。');
    },
  });
  const decision = useMutation({
    mutationFn: ({ id, decision: value }: { decision: RemediationDecision['decision']; id: string }) => decideRemediationProposal(id, {
      decision: value,
      reason: `从案件控制台做出人工决策：${cnLabel(value)}`,
      automated: false,
    }),
    onSuccess: async () => {
      await invalidate();
      message.success('决策已保存。');
    },
  });
  const implementation = useMutation({
    mutationFn: (id: string) => createRemediationImplementation(id, {
      implementation_ref: `case-console://${caseId}/${Date.now()}`,
      description: '从案件控制台录入的修复实现记录。',
      verification_notes: '已准备进入受控复测。',
    }),
    onSuccess: async () => {
      await invalidate();
      message.success('修复实现已记录。');
    },
  });
  const retest = useMutation({
    mutationFn: (value: RetestFormValue) => createRetestRequest(caseId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('复测已入队。');
    },
  });
  const comparison = useMutation({
    mutationFn: getRetestComparison,
    onSuccess: async () => {
      await invalidate();
      message.success('对比已生成。');
    },
  });
  const disposition = useMutation({
    mutationFn: (value: CaseDispositionCreate) => createCaseDisposition(caseId, value),
    onSuccess: async () => {
      await invalidate();
      message.success('处置结论已记录。');
    },
  });
  const report = useMutation({
    mutationFn: () => generateCaseReport(caseId, { title: `案件报告 ${caseId.slice(0, 8)}` }),
    onSuccess: async () => {
      await invalidate();
      message.success('报告已生成。');
    },
  });
  const closeCase = useMutation({
    mutationFn: () => closeVulnerabilityCase(caseId, {
      expected_version: detail.data?.case.version ?? 1,
      reason: '从案件控制台关闭',
    }),
    onSuccess: async () => {
      await invalidate();
      message.success('案件已关闭。');
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
          <Link to="/cases"><Button>返回案件列表</Button></Link>
          <Typography.Title level={2}>{currentCase.title}</Typography.Title>
          <Space>
            <Tag color={tagColor(currentCase.status)}>{cnLabel(currentCase.status)}</Tag>
            <Tag>{cnLabel(currentCase.severity)}</Tag>
            <Typography.Text type="secondary">版本 {currentCase.version}</Typography.Text>
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
      <Card title="概览">
        <Descriptions column={2} bordered size="small">
          <Descriptions.Item label="案件 ID">{currentCase.id}</Descriptions.Item>
          <Descriptions.Item label="项目">{currentCase.project_id}</Descriptions.Item>
          <Descriptions.Item label="租户">{currentCase.tenant_id}</Descriptions.Item>
          <Descriptions.Item label="来源">{cnLabel(currentCase.source)}</Descriptions.Item>
          <Descriptions.Item label="摘要" span={2}>{currentCase.summary}</Descriptions.Item>
          <Descriptions.Item label="创建时间">{currentCase.created_at}</Descriptions.Item>
          <Descriptions.Item label="更新时间">{currentCase.updated_at}</Descriptions.Item>
        </Descriptions>
      </Card>
      <Card title="人工流程控制" className="section-gap">
        <Space direction="vertical" className="full-width">
          <Form<TransitionFormValue>
            layout="inline"
            initialValues={{ status: currentCase.status }}
            onFinish={(value) => transition.mutate(value)}
          >
            <Form.Item name="status" label="下一状态">
              <Select options={CASE_STATUSES.map((value) => ({ value, label: cnLabel(value) }))} className="wide-select" />
            </Form.Item>
            <Form.Item>
              <Button htmlType="submit" loading={transition.isPending}>切换状态</Button>
            </Form.Item>
          </Form>
          <Space wrap>
            <Button loading={report.isPending} onClick={() => report.mutate()}>生成报告</Button>
            <Button danger loading={closeCase.isPending} disabled={currentCase.status === 'CLOSED'} onClick={() => closeCase.mutate()}>关闭案件</Button>
          </Space>
        </Space>
      </Card>
      <Tabs
        className="section-gap"
        items={[
          {
            key: 'findings',
            label: `发现项（${data.findings.length}）`,
            children: (
              <Space direction="vertical" className="full-width">
                <Form<CaseFindingCreate>
                  layout="vertical"
                  initialValues={{ risk_level: currentCase.severity, status: 'CANDIDATE' }}
                  onFinish={(value) => finding.mutate(value)}
                >
                  <Space wrap align="start">
                    <Form.Item name="title" label="标题" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name="description" label="描述" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name="validation_execution_id" label="验证执行"><Input /></Form.Item>
                    <Form.Item name="evidence_id" label="证据 ID"><Input /></Form.Item>
                    <Form.Item name="status" label="状态"><Select options={['CANDIDATE', 'VALIDATED', 'FALSE_POSITIVE', 'INCONCLUSIVE'].map((value) => ({ value, label: cnLabel(value) }))} /></Form.Item>
                    <Form.Item name="risk_level" label="风险"><Select options={['informational', 'low', 'medium', 'high', 'critical'].map((value) => ({ value, label: cnLabel(value) }))} /></Form.Item>
                    <Form.Item label=" "><Button htmlType="submit" loading={finding.isPending}>添加发现项</Button></Form.Item>
                  </Space>
                </Form>
                <Table<CaseFinding>
                  size="small"
                  rowKey="id"
                  dataSource={data.findings}
                  columns={[
                    { title: '标题', dataIndex: 'title' },
                    { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={tagColor(value)}>{cnLabel(value)}</Tag> },
                    { title: '执行实例', dataIndex: 'validation_execution_id', ellipsis: true },
                    { title: '证据', dataIndex: 'evidence_id', ellipsis: true },
                    { title: '风险', dataIndex: 'risk_level', render: (value: string) => cnLabel(value) },
                  ]}
                />
              </Space>
            ),
          },
          {
            key: 'remediation',
            label: '修复',
            children: (
              <Space direction="vertical" className="full-width">
                <Form<RemediationProposalCreate>
                  layout="vertical"
                  initialValues={{ source: 'MANUAL', risk_level: 'medium' }}
                  onFinish={(value) => proposal.mutate({ ...value, knowledge_refs: value.knowledge_refs ?? [], provenance: value.provenance ?? {} })}
                >
                  <Space wrap align="start">
                    <Form.Item name="source" label="来源"><Select options={['AI_GENERATED', 'KNOWLEDGE_BASE', 'VENDOR_ADVISORY', 'MANUAL'].map((value) => ({ value, label: cnLabel(value) }))} /></Form.Item>
                    <Form.Item name="title" label="标题" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name="description" label="描述" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name="risk_level" label="风险"><Select options={['low', 'medium', 'high'].map((value) => ({ value, label: cnLabel(value) }))} /></Form.Item>
                    <Form.Item label=" "><Button htmlType="submit" loading={proposal.isPending}>添加建议</Button></Form.Item>
                  </Space>
                </Form>
                <Table<RemediationProposal>
                  size="small"
                  rowKey="id"
                  dataSource={data.remediation_proposals}
                  columns={[
                    { title: '标题', dataIndex: 'title' },
                    { title: '来源', dataIndex: 'source', render: (value: string) => cnLabel(value) },
                    { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={tagColor(value)}>{cnLabel(value)}</Tag> },
                    { title: '风险', dataIndex: 'risk_level', render: (value: string) => cnLabel(value) },
                    {
                      title: '人工决策',
                      render: (_: unknown, record) => (
                        <Space>
                          <Button size="small" loading={decision.isPending} onClick={() => decision.mutate({ id: record.id, decision: 'APPROVED' })}>批准</Button>
                          <Button size="small" danger loading={decision.isPending} onClick={() => decision.mutate({ id: record.id, decision: 'REJECTED' })}>拒绝</Button>
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
                    { title: '决策', dataIndex: 'decision', render: (value: string) => <Tag color={tagColor(value)}>{cnLabel(value)}</Tag> },
                    { title: '原因', dataIndex: 'reason' },
                    { title: '决策人', dataIndex: 'decided_by' },
                    {
                      title: '修复实现',
                      render: (_: unknown, record) => (
                        <Button size="small" disabled={record.decision !== 'APPROVED'} loading={implementation.isPending} onClick={() => implementation.mutate(record.id)}>记录实现</Button>
                      ),
                    },
                  ]}
                />
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.remediation_implementations}
                  columns={[
                    { title: '实现引用', dataIndex: 'implementation_ref' },
                    { title: '描述', dataIndex: 'description' },
                    { title: '实现人', dataIndex: 'implemented_by' },
                    { title: '实现时间', dataIndex: 'implemented_at' },
                  ]}
                />
              </Space>
            ),
          },
          {
            key: 'retest',
            label: '复测与对比',
            children: (
              <Space direction="vertical" className="full-width">
                <Form<RetestFormValue>
                  layout="inline"
                  disabled={!validatedFindings.length || !approvedDecisions.length}
                  onFinish={(value) => retest.mutate(value)}
                >
                  <Form.Item name="finding_id" label="发现项" rules={[{ required: true }]}><Select options={findingOptions} className="wide-select" /></Form.Item>
                  <Form.Item name="original_execution_id" label="原始执行" rules={[{ required: true }]}><Select options={originalExecutionOptions} className="wide-select" /></Form.Item>
                  <Form.Item name="remediation_implementation_id" label="修复实现" rules={[{ required: true }]}><Select options={implementationOptions} className="wide-select" /></Form.Item>
                  <Form.Item><Button htmlType="submit" loading={retest.isPending}>复测入队</Button></Form.Item>
                </Form>
                <Table<RetestRequest>
                  size="small"
                  rowKey="id"
                  dataSource={data.retests}
                  columns={[
                    { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={tagColor(value)}>{cnLabel(value)}</Tag> },
                    { title: '原始执行', dataIndex: 'original_execution_id', ellipsis: true },
                    { title: '复测执行', dataIndex: 'retest_execution_id', ellipsis: true },
                    { title: '模板', dataIndex: 'template_id' },
                    {
                      title: '对比',
                      render: (_: unknown, record) => (
                        <Button size="small" loading={comparison.isPending} onClick={() => comparison.mutate(record.id)}>生成对比</Button>
                      ),
                    },
                  ]}
                />
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.comparisons}
                  columns={[
                    { title: '结果', dataIndex: 'result', render: (value: string) => <Tag color={tagColor(value)}>{cnLabel(value)}</Tag> },
                    { title: '初始状态', dataIndex: 'initial_status', render: (value: string) => cnLabel(value) },
                    { title: '复测状态', dataIndex: 'retest_status', render: (value: string) => cnLabel(value) },
                    { title: '残余风险', dataIndex: 'residual_risk', render: (value: string) => cnLabel(value) },
                    { title: '建议', dataIndex: 'recommendation' },
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
                  <Form.Item name="disposition" label="处置结论"><Select options={['REMEDIATED', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'INCONCLUSIVE'].map((value) => ({ value, label: cnLabel(value) }))} /></Form.Item>
                  <Form.Item name="reason" label="原因" rules={[{ required: true }]}><Input /></Form.Item>
                  <Form.Item name="residual_risk" label="残余风险"><Input /></Form.Item>
                  <Form.Item><Button htmlType="submit" loading={disposition.isPending}>人工确认</Button></Form.Item>
                </Form>
              </Space>
            ),
          },
          {
            key: 'reports',
            label: '报告与审计',
            children: (
              <Space direction="vertical" className="full-width">
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.dispositions}
                  columns={[
                    { title: '处置结论', dataIndex: 'disposition', render: (value: string) => <Tag color={tagColor(value)}>{cnLabel(value)}</Tag> },
                    { title: '原因', dataIndex: 'reason' },
                    { title: '人工确认', dataIndex: 'human_confirmed', render: (value: boolean) => cnBoolean(value) },
                  ]}
                />
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.reports}
                  columns={[
                    { title: '标题', dataIndex: 'title' },
                    { title: '生成者', dataIndex: 'generated_by' },
                    { title: '生成时间', dataIndex: 'generated_at' },
                  ]}
                />
                <Table
                  size="small"
                  rowKey="id"
                  dataSource={data.audit_events}
                  columns={[
                    { title: '动作', dataIndex: 'action' },
                    { title: '操作者', dataIndex: 'actor_id' },
                    { title: '资源', dataIndex: 'resource_id', ellipsis: true },
                    { title: '时间', dataIndex: 'timestamp' },
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
