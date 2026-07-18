import type {
  CompliancePackage,
  DeploymentRecord,
  DriftDetectionResult,
  EnvironmentPromotionCreate,
  EnvironmentPromotionResult,
  ReleaseApprovalCreate,
  ReleaseApproval,
  ReleaseArtifact,
  ReleaseArtifactCreate,
  ReleaseArtifactDetail,
  ReleaseCandidate,
  ReleaseCandidateCreate,
  ReleaseCandidateDetail,
  ReleaseException,
  ReleaseExceptionCreate,
  ReleaseGateEvaluationRequest,
  ReleaseGateResult,
  RollbackCreate,
  RollbackRecord,
} from '@vulnlab/shared-types';

import { apiClient, ApiError } from './api';

function errorMessage(error: unknown, fallback: string): string {
  if (typeof error === 'object' && error !== null && 'detail' in error) {
    const detail = (error as { detail?: unknown }).detail;
    if (typeof detail === 'string') return detail;
  }
  return fallback;
}

function requireData<T>(
  data: T | undefined,
  error: unknown,
  response: Response,
  fallback: string,
): T {
  if (data === undefined) throw new ApiError(errorMessage(error, fallback), response.status);
  return data;
}

function idempotencyKey(prefix: string) {
  return `${prefix}-${crypto.randomUUID()}`;
}

export async function listReleaseArtifacts(limit = 100): Promise<ReleaseArtifact[]> {
  const { data, error, response } = await apiClient.GET('/release-artifacts', {
    params: { query: { limit } },
  });
  return requireData(data, error, response, 'Unable to read release artifacts');
}

export async function getReleaseArtifact(artifactId: string): Promise<ReleaseArtifactDetail> {
  const { data, error, response } = await apiClient.GET('/release-artifacts/{artifact_id}', {
    params: { path: { artifact_id: artifactId } },
  });
  return requireData(data, error, response, 'Unable to read release artifact');
}

export async function registerReleaseArtifact(
  value: ReleaseArtifactCreate,
): Promise<ReleaseArtifactDetail> {
  const { data, error, response } = await apiClient.POST('/release-artifacts', {
    params: { header: { 'Idempotency-Key': idempotencyKey('release-artifact') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to register release artifact');
}

export async function listReleaseCandidates(limit = 100): Promise<ReleaseCandidate[]> {
  const { data, error, response } = await apiClient.GET('/release-candidates', {
    params: { query: { limit } },
  });
  return requireData(data, error, response, 'Unable to read release candidates');
}

export async function getReleaseCandidate(candidateId: string): Promise<ReleaseCandidateDetail> {
  const { data, error, response } = await apiClient.GET('/release-candidates/{candidate_id}', {
    params: { path: { candidate_id: candidateId } },
  });
  return requireData(data, error, response, 'Unable to read release candidate');
}

export async function createReleaseCandidate(
  value: ReleaseCandidateCreate,
): Promise<ReleaseCandidateDetail> {
  const { data, error, response } = await apiClient.POST('/release-candidates', {
    params: { header: { 'Idempotency-Key': idempotencyKey('release-candidate') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create release candidate');
}

export async function evaluateReleaseCandidate(
  candidateId: string,
  value: ReleaseGateEvaluationRequest,
): Promise<ReleaseGateResult[]> {
  const { data, error, response } = await apiClient.POST(
    '/release-candidates/{candidate_id}/evaluate',
    {
      params: {
        path: { candidate_id: candidateId },
        header: { 'Idempotency-Key': idempotencyKey('release-gate') },
      },
      body: value,
    },
  );
  return requireData(data, error, response, 'Unable to evaluate release gates');
}

export async function approveReleaseCandidate(
  candidateId: string,
  value: ReleaseApprovalCreate,
): Promise<ReleaseApproval> {
  const { data, error, response } = await apiClient.POST(
    '/release-candidates/{candidate_id}/approvals',
    {
      params: {
        path: { candidate_id: candidateId },
        header: { 'Idempotency-Key': idempotencyKey('release-approval') },
      },
      body: value,
    },
  );
  return requireData(data, error, response, 'Unable to approve release candidate');
}

export async function requestReleaseException(
  candidateId: string,
  value: ReleaseExceptionCreate,
): Promise<ReleaseException> {
  const { data, error, response } = await apiClient.POST(
    '/release-candidates/{candidate_id}/exceptions',
    {
      params: {
        path: { candidate_id: candidateId },
        header: { 'Idempotency-Key': idempotencyKey('release-exception') },
      },
      body: value,
    },
  );
  return requireData(data, error, response, 'Unable to request release exception');
}

export async function promoteReleaseCandidate(
  candidateId: string,
  value: EnvironmentPromotionCreate,
): Promise<EnvironmentPromotionResult> {
  const { data, error, response } = await apiClient.POST(
    '/release-candidates/{candidate_id}/promotions',
    {
      params: {
        path: { candidate_id: candidateId },
        header: { 'Idempotency-Key': idempotencyKey(`release-promote-${value.environment}`) },
      },
      body: value,
    },
  );
  return requireData(data, error, response, 'Unable to promote release candidate');
}

export async function getDeployment(deploymentId: string): Promise<DeploymentRecord> {
  const { data, error, response } = await apiClient.GET('/deployments/{deployment_id}', {
    params: { path: { deployment_id: deploymentId } },
  });
  return requireData(data, error, response, 'Unable to read deployment');
}

export async function rollbackDeployment(
  deploymentId: string,
  value: RollbackCreate,
): Promise<RollbackRecord> {
  const { data, error, response } = await apiClient.POST(
    '/deployments/{deployment_id}/rollback',
    {
      params: {
        path: { deployment_id: deploymentId },
        header: { 'Idempotency-Key': idempotencyKey('release-rollback') },
      },
      body: value,
    },
  );
  return requireData(data, error, response, 'Unable to rollback deployment');
}

export async function detectDeploymentDrift(
  deploymentId: string,
): Promise<DriftDetectionResult> {
  const { data, error, response } = await apiClient.GET('/deployments/{deployment_id}/drift', {
    params: { path: { deployment_id: deploymentId } },
  });
  return requireData(data, error, response, 'Unable to detect deployment drift');
}

export async function generateCompliancePackage(
  candidateId: string,
): Promise<CompliancePackage> {
  const { data, error, response } = await apiClient.POST(
    '/release-candidates/{candidate_id}/compliance-package',
    {
      params: {
        path: { candidate_id: candidateId },
        header: { 'Idempotency-Key': idempotencyKey('release-compliance') },
      },
    },
  );
  return requireData(data, error, response, 'Unable to generate compliance package');
}
