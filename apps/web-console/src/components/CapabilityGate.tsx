import type { ReactNode } from 'react';
import { Alert } from 'antd';

interface CapabilityGateProps {
  enabled: boolean;
  children: ReactNode;
  reason?: string;
}

export function CapabilityGate({ enabled, children, reason }: CapabilityGateProps) {
  if (enabled) return children;
  return (
    <Alert
      showIcon
      type="info"
      message="该能力尚未开放"
      description={reason ?? '当前仅交付 P0 架构与工程基线。'}
    />
  );
}
