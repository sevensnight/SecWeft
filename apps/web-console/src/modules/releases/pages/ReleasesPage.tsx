import { useMutation, useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { ReleaseArtifactCreate, ReleaseCandidate } from '@vulnlab/shared-types';
import { App, Button, Card, Space, Table, Tag, Typography } from 'antd';

import { queryClient } from '../../../app/query-client';
import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnLabel } from '../../../i18n/formatters';
import {
  createReleaseCandidate,
  listReleaseArtifacts,
  listReleaseCandidates,
  registerReleaseArtifact,
} from '../../../services/releases';

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);
const SHA_D = 'd'.repeat(64);
const SHA_E = 'e'.repeat(64);
const SHA_F = 'f'.repeat(64);

function gateColor(status: string) {
  if (['deployed', 'approved', 'frozen', 'evaluated'].includes(status)) return 'green';
  if (['blocked', 'failed', 'rolled_back'].includes(status)) return 'red';
  return 'blue';
}

function sampleArtifactPayload(suffix: string): ReleaseArtifactCreate {
  const imageDigest = `registry.local/vulnlab/control-plane-${suffix}@sha256:${SHA_A}`;
  return {
    tenant_id: 'system',
    project_id: 'project-alpha',
    name: `示例产物 ${suffix}`,
    artifact_type: 'container',
    digest: imageDigest,
    repository: 'registry.local/vulnlab/control-plane',
    source_commit: SHA_B.slice(0, 40),
    metadata: {
      build_record: 'local-deterministic-web-console',
      supply_chain_scope: 'metadata-only',
    },
    sbom: {
      format: 'CycloneDX',
      generator: 'vulnlab-web-console-sample',
      generated_at: new Date().toISOString(),
      artifact_digest: imageDigest,
      document_digest: `sha256:${SHA_C}`,
      component_count: 42,
      license_summary: { MIT: 20, Apache_2_0: 22 },
      vulnerability_summary: { critical: 0, high: 0 },
      document_ref: `sbom://sample/${suffix}`,
    },
    provenance: {
      subject_digest: imageDigest,
      source_repository: 'https://github.com/example/vulnlab',
      source_commit: SHA_B.slice(0, 40),
      builder_workflow: '.github/workflows/ci.yml',
      statement_digest: `sha256:${SHA_D}`,
      predicate_type: 'https://slsa.dev/provenance/v1',
      verified: true,
      metadata: { oidc_issuer: 'https://token.actions.githubusercontent.com' },
    },
    signature: {
      signature_digest: `sha256:${SHA_E}`,
      signature_identity: 'https://github.com/example/vulnlab/.github/workflows/ci.yml@refs/heads/main',
      certificate_issuer: 'https://token.actions.githubusercontent.com',
      verified: true,
      verification_error: '',
    },
    security_scan: {
      scanner: 'trivy',
      severity_summary: { critical: 0, high: 0, medium: 1 },
      critical_count: 0,
      high_count: 0,
      unresolved_critical: false,
      scan_digest: `sha256:${SHA_F}`,
    },
    license_scan: {
      scanner: 'license-policy',
      license_summary: { allowed: 42, prohibited: 0 },
      prohibited_licenses: [],
      passed: true,
      scan_digest: `sha256:${SHA_A}`,
    },
  };
}

export function ReleasesPage() {
  const { message } = App.useApp();
  const artifacts = useQuery({
    queryKey: ['release-artifacts'],
    queryFn: () => listReleaseArtifacts(100),
  });
  const candidates = useQuery({
    queryKey: ['release-candidates'],
    queryFn: () => listReleaseCandidates(100),
  });
  const createSample = useMutation({
    mutationFn: async () => {
      const suffix = Date.now().toString(36);
      const artifact = await registerReleaseArtifact(sampleArtifactPayload(suffix));
      return createReleaseCandidate({
        tenant_id: artifact.tenant_id,
        project_id: artifact.project_id,
        name: `示例发布候选 ${suffix}`,
        artifact_id: artifact.id,
        configuration_hash: SHA_B,
        migration_set: ['0001-0013'],
        helm_chart_digest: `sha256:${SHA_C}`,
        metadata: {
          p0_p12_baseline: true,
          p11_evaluation_gates: true,
          source_tree_clean: true,
          p12_authoritative_runtime: {
            status: 'READINESS_COMPLETE',
            runtime: false,
            runtime_not_claimed: true,
          },
        },
      });
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['release-artifacts'] }),
        queryClient.invalidateQueries({ queryKey: ['release-candidates'] }),
      ]);
      message.success('发布候选已创建。');
    },
  });
  const firstError = artifacts.error ?? candidates.error ?? createSample.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>发布治理</Typography.Title>
        <Typography.Text type="secondary">
          登记不可变产物、冻结发布候选、评估门禁，并跟踪审批、提升、回滚、漂移与合规证据。
        </Typography.Text>
      </div>
      {artifacts.isPending || candidates.isPending ? <LoadingState /> : null}
      {firstError ? (
        <QueryErrorState
          error={firstError}
          onRetry={() => {
            createSample.reset();
            void artifacts.refetch();
            void candidates.refetch();
          }}
        />
      ) : null}
      <Card
        title="供应链发布候选"
        extra={
          <Button type="primary" loading={createSample.isPending} onClick={() => createSample.mutate()}>
            创建示例发布候选
          </Button>
        }
      >
        <Typography.Paragraph>
          示例流程只登记一个包含 SBOM、来源证明、签名、漏洞扫描和许可证扫描元数据的不可变容器摘要，
          然后冻结发布候选；不会执行构建、扫描器、Shell、PoC 或部署。
        </Typography.Paragraph>
      </Card>
      <Card title="发布候选" className="section-gap" loading={candidates.isPending}>
        <Table<ReleaseCandidate>
          size="small"
          rowKey="id"
          dataSource={candidates.data ?? []}
          columns={[
            {
              title: '候选',
              dataIndex: 'id',
              render: (value: string, record) => (
                <Space direction="vertical" size={0}>
                  <Link to="/releases/$candidateId" params={{ candidateId: value }}>
                    {record.name}
                  </Link>
                  <Typography.Text type="secondary">{value.slice(0, 8)}</Typography.Text>
                </Space>
              ),
            },
            {
              title: '状态',
              dataIndex: 'status',
              render: (value: string) => <Tag color={gateColor(value)}>{cnLabel(value)}</Tag>,
            },
            { title: '项目', dataIndex: 'project_id' },
            { title: '源码提交', dataIndex: 'source_commit', render: (value: string) => value.slice(0, 12) },
            {
              title: '镜像摘要',
              dataIndex: 'image_digest',
              render: (value: string) => <Typography.Text code>{value.slice(0, 48)}...</Typography.Text>,
            },
            { title: '版本', dataIndex: 'version' },
            { title: '更新时间', dataIndex: 'updated_at' },
          ]}
        />
      </Card>
      <Card title="已登记产物" className="section-gap" loading={artifacts.isPending}>
        <Table
          size="small"
          rowKey="id"
          dataSource={artifacts.data ?? []}
          columns={[
            { title: '产物', dataIndex: 'name' },
            { title: '类型', dataIndex: 'artifact_type', render: (value: string) => cnLabel(value) },
            { title: '项目', dataIndex: 'project_id' },
            {
              title: '摘要',
              dataIndex: 'digest',
              render: (value: string) => <Typography.Text code>{value.slice(0, 56)}...</Typography.Text>,
            },
            { title: '创建时间', dataIndex: 'created_at' },
          ]}
        />
      </Card>
    </section>
  );
}
