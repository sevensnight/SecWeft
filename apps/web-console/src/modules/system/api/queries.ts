import { queryOptions } from '@tanstack/react-query';

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
