import type {
  AcceptanceRun,
  AcceptanceRunCreate,
  AcceptanceStatus,
  ComplianceControl,
  ComplianceEvidencePackage,
  ComplianceEvidencePackageCreate,
  DataDeletionRequest,
  DataDeletionRequestCreate,
  DataExport,
  DataExportCreate,
  DeliveryPackage,
  DeliveryPackageCreate,
  LegalHold,
  LegalHoldCreate,
  ProductionReadiness,
  RequirementTraceabilityItem,
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

export async function listAcceptanceRequirements(): Promise<RequirementTraceabilityItem[]> {
  const { data, error, response } = await apiClient.GET('/acceptance/requirements');
  return requireData(data, error, response, 'Unable to read requirement traceability');
}

export async function getAcceptanceStatus(): Promise<AcceptanceStatus> {
  const { data, error, response } = await apiClient.GET('/acceptance/status');
  return requireData(data, error, response, 'Unable to read acceptance status');
}

export async function runEnterpriseAcceptance(value: AcceptanceRunCreate): Promise<AcceptanceRun> {
  const { data, error, response } = await apiClient.POST('/acceptance/runs', {
    params: { header: { 'Idempotency-Key': idempotencyKey('acceptance-run') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to run acceptance');
}

export async function generateDeliveryPackage(
  value: DeliveryPackageCreate,
): Promise<DeliveryPackage> {
  const { data, error, response } = await apiClient.POST('/delivery-packages', {
    params: { header: { 'Idempotency-Key': idempotencyKey('delivery-package') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to generate delivery package');
}

export async function getDeliveryPackage(packageId: string): Promise<DeliveryPackage> {
  const { data, error, response } = await apiClient.GET('/delivery-packages/{package_id}', {
    params: { path: { package_id: packageId } },
  });
  return requireData(data, error, response, 'Unable to read delivery package');
}

export async function listComplianceControls(): Promise<ComplianceControl[]> {
  const { data, error, response } = await apiClient.GET('/compliance/controls');
  return requireData(data, error, response, 'Unable to read compliance controls');
}

export async function generateComplianceEvidencePackage(
  value: ComplianceEvidencePackageCreate,
): Promise<ComplianceEvidencePackage> {
  const { data, error, response } = await apiClient.POST('/compliance/evidence-packages', {
    params: { header: { 'Idempotency-Key': idempotencyKey('compliance-evidence') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to generate compliance evidence package');
}

export async function exportTenantData(value: DataExportCreate): Promise<DataExport> {
  const { data, error, response } = await apiClient.POST('/data-governance/export', {
    params: { header: { 'Idempotency-Key': idempotencyKey('tenant-data-export') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to export tenant data');
}

export async function requestDataDeletion(
  value: DataDeletionRequestCreate,
): Promise<DataDeletionRequest> {
  const { data, error, response } = await apiClient.POST('/data-governance/deletion-requests', {
    params: { header: { 'Idempotency-Key': idempotencyKey('tenant-data-delete') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to request data deletion');
}

export async function createLegalHold(value: LegalHoldCreate): Promise<LegalHold> {
  const { data, error, response } = await apiClient.POST('/data-governance/legal-holds', {
    params: { header: { 'Idempotency-Key': idempotencyKey('legal-hold') } },
    body: value,
  });
  return requireData(data, error, response, 'Unable to create legal hold');
}

export async function getProductionReadiness(): Promise<ProductionReadiness> {
  const { data, error, response } = await apiClient.GET('/readiness/production');
  return requireData(data, error, response, 'Unable to read production readiness');
}
