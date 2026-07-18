import { useMutation, useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { ReleaseArtifactCreate, ReleaseCandidate } from '@vulnlab/shared-types';
import { App, Button, Card, Space, Table, Tag, Typography } from 'antd';

import { queryClient } from '../../../app/query-client';
import { LoadingState } from '../../../components/LoadingState';
import { QueryErrorState } from '../../../components/QueryErrorState';
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
    name: `P13 sample artifact ${suffix}`,
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
        name: `P13 sample RC ${suffix}`,
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
      message.success('Release candidate created.');
    },
  });
  const firstError = artifacts.error ?? candidates.error ?? createSample.error;

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>Release Governance</Typography.Title>
        <Typography.Text type="secondary">
          Register immutable artifacts, freeze release candidates, evaluate gates, track approvals,
          promotions, rollbacks, drift, and compliance evidence.
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
        title="Supply-chain release candidate"
        extra={
          <Button type="primary" loading={createSample.isPending} onClick={() => createSample.mutate()}>
            Create sample RC
          </Button>
        }
      >
        <Typography.Paragraph>
          The sample flow registers one immutable container digest with SBOM, provenance, signature,
          vulnerability scan, and license scan metadata, then freezes a release candidate. It does not
          execute a build, scanner, shell, PoC, or deployment.
        </Typography.Paragraph>
      </Card>
      <Card title="Release candidates" className="section-gap" loading={candidates.isPending}>
        <Table<ReleaseCandidate>
          size="small"
          rowKey="id"
          dataSource={candidates.data ?? []}
          columns={[
            {
              title: 'Candidate',
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
              title: 'Status',
              dataIndex: 'status',
              render: (value: string) => <Tag color={gateColor(value)}>{value}</Tag>,
            },
            { title: 'Project', dataIndex: 'project_id' },
            { title: 'Commit', dataIndex: 'source_commit', render: (value: string) => value.slice(0, 12) },
            {
              title: 'Image digest',
              dataIndex: 'image_digest',
              render: (value: string) => <Typography.Text code>{value.slice(0, 48)}...</Typography.Text>,
            },
            { title: 'Version', dataIndex: 'version' },
            { title: 'Updated', dataIndex: 'updated_at' },
          ]}
        />
      </Card>
      <Card title="Registered artifacts" className="section-gap" loading={artifacts.isPending}>
        <Table
          size="small"
          rowKey="id"
          dataSource={artifacts.data ?? []}
          columns={[
            { title: 'Artifact', dataIndex: 'name' },
            { title: 'Type', dataIndex: 'artifact_type' },
            { title: 'Project', dataIndex: 'project_id' },
            {
              title: 'Digest',
              dataIndex: 'digest',
              render: (value: string) => <Typography.Text code>{value.slice(0, 56)}...</Typography.Text>,
            },
            { title: 'Created', dataIndex: 'created_at' },
          ]}
        />
      </Card>
    </section>
  );
}
