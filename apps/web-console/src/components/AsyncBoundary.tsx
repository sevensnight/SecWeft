import { Suspense, type ReactNode } from 'react';

import { LoadingState } from './LoadingState';

export function AsyncBoundary({ children }: { children: ReactNode }) {
  return <Suspense fallback={<LoadingState />}>{children}</Suspense>;
}
