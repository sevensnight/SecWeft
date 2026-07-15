import { queryOptions } from '@tanstack/react-query';

import { getSystemRequirements } from '../../../services/api';

export const systemRequirementsQuery = () => queryOptions({
  queryKey: ['system', 'requirements'],
  queryFn: getSystemRequirements,
  staleTime: 30_000,
});
