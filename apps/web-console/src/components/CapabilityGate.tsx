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
      description={reason ?? '当前阶段仅展示受控企业控制台能力。'}
    />
  );
}
