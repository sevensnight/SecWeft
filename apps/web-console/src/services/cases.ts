import type {
  CaseCloseRequest,
  CaseDisposition,
  CaseDispositionCreate,
  CaseFinding,
  CaseFindingCreate,
  CaseReport,
  CaseReportCreate,
  RemediationDecision,
  RemediationDecisionCreate,
  RemediationImplementation,
  RemediationImplementationCreate,
  RemediationProposal,
  RemediationProposalCreate,
  RetestRequest,
  RetestRequestCreate,
  ValidationComparison,
  VulnerabilityCase,
  VulnerabilityCaseCreate,
  VulnerabilityCaseDetail,
  VulnerabilityCasePatch,
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

export async function listVulnerabilityCases(limit = 100): Promise<VulnerabilityCase[]> {
  const { data, error, response } = await apiClient.GET('/vulnerability-cases', {
    params: { query: { limit } },
  });
  return requireData(data, error, response, 'Unable to read vulnerability cases');
}

export async function createVulnerabilityCase(
  value: VulnerabilityCaseCreate,
): Promise<VulnerabilityCase> {
  const { data, error, response } = await apiClient.POST('/vulnerability-cases', {
    params: { header: { 'Idempotency-Key': idempotencyKey('case-create') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create vulnerability case');
}

export async function getVulnerabilityCaseDetail(caseId: string): Promise<VulnerabilityCaseDetail> {
  const { data, error, response } = await apiClient.GET('/vulnerability-cases/{case_id}', {
    params: { path: { case_id: caseId } },
  });
  return requireData(data, error, response, 'Unable to read vulnerability case');
}

export async function updateVulnerabilityCase(
  caseId: string,
  value: VulnerabilityCasePatch,
): Promise<VulnerabilityCase> {
  const { data, error, response } = await apiClient.PATCH('/vulnerability-cases/{case_id}', {
    params: {
      path: { case_id: caseId },
      header: { 'Idempotency-Key': idempotencyKey('case-update') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to update vulnerability case');
}

export async function createCaseFinding(
  caseId: string,
  value: CaseFindingCreate,
): Promise<CaseFinding> {
  const { data, error, response } = await apiClient.POST('/vulnerability-cases/{case_id}/findings', {
    params: {
      path: { case_id: caseId },
      header: { 'Idempotency-Key': idempotencyKey('case-finding') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create case finding');
}

export async function createRemediationProposal(
  caseId: string,
  value: RemediationProposalCreate,
): Promise<RemediationProposal> {
  const { data, error, response } = await apiClient.POST('/vulnerability-cases/{case_id}/remediation-proposals', {
    params: {
      path: { case_id: caseId },
      header: { 'Idempotency-Key': idempotencyKey('remediation-proposal') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create remediation proposal');
}

export async function decideRemediationProposal(
  proposalId: string,
  value: RemediationDecisionCreate,
): Promise<RemediationDecision> {
  const { data, error, response } = await apiClient.POST('/remediation-proposals/{proposal_id}/decisions', {
    params: {
      path: { proposal_id: proposalId },
      header: { 'Idempotency-Key': idempotencyKey('remediation-decision') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to decide remediation proposal');
}

export async function createRemediationImplementation(
  decisionId: string,
  value: RemediationImplementationCreate,
): Promise<RemediationImplementation> {
  const { data, error, response } = await apiClient.POST('/remediation-decisions/{decision_id}/implementations', {
    params: {
      path: { decision_id: decisionId },
      header: { 'Idempotency-Key': idempotencyKey('remediation-implementation') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create remediation implementation');
}

export async function createRetestRequest(
  caseId: string,
  value: RetestRequestCreate,
): Promise<RetestRequest> {
  const { data, error, response } = await apiClient.POST('/vulnerability-cases/{case_id}/retests', {
    params: {
      path: { case_id: caseId },
      header: { 'Idempotency-Key': idempotencyKey('case-retest') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create retest request');
}

export async function getRetestComparison(retestId: string): Promise<ValidationComparison> {
  const { data, error, response } = await apiClient.GET('/retests/{retest_id}/comparison', {
    params: { path: { retest_id: retestId } },
  });
  return requireData(data, error, response, 'Unable to generate retest comparison');
}

export async function createCaseDisposition(
  caseId: string,
  value: CaseDispositionCreate,
): Promise<CaseDisposition> {
  const { data, error, response } = await apiClient.POST('/vulnerability-cases/{case_id}/disposition', {
    params: {
      path: { case_id: caseId },
      header: { 'Idempotency-Key': idempotencyKey('case-disposition') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create case disposition');
}

export async function closeVulnerabilityCase(
  caseId: string,
  value: CaseCloseRequest,
): Promise<VulnerabilityCase> {
  const { data, error, response } = await apiClient.POST('/vulnerability-cases/{case_id}/close', {
    params: {
      path: { case_id: caseId },
      header: { 'Idempotency-Key': idempotencyKey('case-close') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to close vulnerability case');
}

export async function generateCaseReport(
  caseId: string,
  value: CaseReportCreate,
): Promise<CaseReport> {
  const { data, error, response } = await apiClient.POST('/vulnerability-cases/{case_id}/reports', {
    params: {
      path: { case_id: caseId },
      header: { 'Idempotency-Key': idempotencyKey('case-report') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to generate case report');
}
