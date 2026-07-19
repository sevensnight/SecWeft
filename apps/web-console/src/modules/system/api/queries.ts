import { queryOptions } from '@tanstack/react-query';

import {
  getAcceptanceStatus,
  getProductionReadiness,
  listAcceptanceRequirements,
  listComplianceControls,
} from '../../../services/acceptance';
import { getSystemRequirements, getSystemResilience } from '../../../services/api';

export const systemRequirementsQuery = () => queryOptions({
  queryKey: ['system', 'requirements'],
  queryFn: getSystemRequirements,
  staleTime: 30_000,
});

export const systemResilienceQuery = () =>
  queryOptions({
    queryKey: ['system', 'resilience'],
    queryFn: getSystemResilience,
    staleTime: 15_000,
  });

export const acceptanceRequirementsQuery = () =>
  queryOptions({
    queryKey: ['acceptance', 'requirements'],
    queryFn: listAcceptanceRequirements,
    staleTime: 60_000,
  });

export const acceptanceStatusQuery = () =>
  queryOptions({
    queryKey: ['acceptance', 'status'],
    queryFn: getAcceptanceStatus,
    staleTime: 15_000,
  });

export const complianceControlsQuery = () =>
  queryOptions({
    queryKey: ['compliance', 'controls'],
    queryFn: listComplianceControls,
    staleTime: 60_000,
  });

export const productionReadinessQuery = () =>
  queryOptions({
    queryKey: ['readiness', 'production'],
    queryFn: getProductionReadiness,
    staleTime: 15_000,
  });
