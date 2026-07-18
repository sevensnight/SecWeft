import type {
  EvaluationCase,
  EvaluationCaseCreate,
  EvaluationComparison,
  EvaluationDataset,
  EvaluationDatasetCreate,
  EvaluationFailure,
  EvaluationReview,
  EvaluationReviewCreate,
  EvaluationRun,
  EvaluationRunCreate,
  EvaluationRunDetail,
  EvaluationSuite,
  EvaluationSuiteCreate,
  MetricResult,
  PromotionDecision,
  PromotionDecisionCreate,
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

export async function listEvaluationSuites(limit = 100): Promise<EvaluationSuite[]> {
  const { data, error, response } = await apiClient.GET('/evaluation-suites', {
    params: { query: { limit } },
  });
  return requireData(data, error, response, 'Unable to read evaluation suites');
}

export async function createEvaluationSuite(
  value: EvaluationSuiteCreate,
): Promise<EvaluationSuite> {
  const { data, error, response } = await apiClient.POST('/evaluation-suites', {
    params: { header: { 'Idempotency-Key': idempotencyKey('evaluation-suite') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create evaluation suite');
}

export async function createEvaluationDataset(
  value: EvaluationDatasetCreate,
): Promise<EvaluationDataset> {
  const { data, error, response } = await apiClient.POST('/evaluation-datasets', {
    params: { header: { 'Idempotency-Key': idempotencyKey('evaluation-dataset') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create evaluation dataset');
}

export async function getEvaluationDataset(datasetId: string): Promise<EvaluationDataset> {
  const { data, error, response } = await apiClient.GET('/evaluation-datasets/{dataset_id}', {
    params: { path: { dataset_id: datasetId } },
  });
  return requireData(data, error, response, 'Unable to read evaluation dataset');
}

export async function createEvaluationCase(
  datasetId: string,
  value: EvaluationCaseCreate,
): Promise<EvaluationCase> {
  const { data, error, response } = await apiClient.POST('/evaluation-datasets/{dataset_id}/cases', {
    params: {
      path: { dataset_id: datasetId },
      header: { 'Idempotency-Key': idempotencyKey('evaluation-case') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create evaluation case');
}

export async function createEvaluationRun(value: EvaluationRunCreate): Promise<EvaluationRunDetail> {
  const { data, error, response } = await apiClient.POST('/evaluation-runs', {
    params: { header: { 'Idempotency-Key': idempotencyKey('evaluation-run') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create evaluation run');
}

export async function listEvaluationRuns(limit = 100): Promise<EvaluationRun[]> {
  const { data, error, response } = await apiClient.GET('/evaluation-runs', {
    params: { query: { limit } },
  });
  return requireData(data, error, response, 'Unable to read evaluation runs');
}

export async function getEvaluationRun(runId: string): Promise<EvaluationRunDetail> {
  const { data, error, response } = await apiClient.GET('/evaluation-runs/{run_id}', {
    params: { path: { run_id: runId } },
  });
  return requireData(data, error, response, 'Unable to read evaluation run');
}

export async function listEvaluationMetrics(runId: string): Promise<MetricResult[]> {
  const { data, error, response } = await apiClient.GET('/evaluation-runs/{run_id}/metrics', {
    params: { path: { run_id: runId } },
  });
  return requireData(data, error, response, 'Unable to read evaluation metrics');
}

export async function listEvaluationFailures(runId: string): Promise<EvaluationFailure[]> {
  const { data, error, response } = await apiClient.GET('/evaluation-runs/{run_id}/failures', {
    params: { path: { run_id: runId } },
  });
  return requireData(data, error, response, 'Unable to read evaluation failures');
}

export async function getEvaluationComparison(comparisonId: string): Promise<EvaluationComparison> {
  const { data, error, response } = await apiClient.GET('/evaluation-comparisons/{comparison_id}', {
    params: { path: { comparison_id: comparisonId } },
  });
  return requireData(data, error, response, 'Unable to read evaluation comparison');
}

export async function createEvaluationReview(
  runId: string,
  value: EvaluationReviewCreate,
): Promise<EvaluationReview> {
  const { data, error, response } = await apiClient.POST('/evaluation-runs/{run_id}/reviews', {
    params: {
      path: { run_id: runId },
      header: { 'Idempotency-Key': idempotencyKey('evaluation-review') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create evaluation review');
}

export async function createPromotionDecision(
  runId: string,
  value: PromotionDecisionCreate,
): Promise<PromotionDecision> {
  const { data, error, response } = await apiClient.POST('/evaluation-runs/{run_id}/promotion-decisions', {
    params: {
      path: { run_id: runId },
      header: { 'Idempotency-Key': idempotencyKey('promotion-decision') },
    },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create promotion decision');
}
