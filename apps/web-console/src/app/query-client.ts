import { QueryClient } from '@tanstack/react-query';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      gcTime: 5 * 60_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        if (error instanceof Error && /401|403/.test(error.message)) return false;
        return failureCount < 2;
      },
      staleTime: 10_000,
    },
  },
});
