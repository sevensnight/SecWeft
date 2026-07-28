import { Tag } from 'antd';
import type { ReactNode } from 'react';

const COLORS: Record<string, string> = {
  approved: 'blue',
  failed: 'red',
  pending_approval: 'gold',
  running: 'processing',
  succeeded: 'green',
};

export interface StatusPillProps {
  label?: ReactNode;
  status: string;
}

export function StatusPill({ label, status }: StatusPillProps) {
  return <Tag color={COLORS[status] ?? 'default'}>{label ?? status.replaceAll('_', ' ')}</Tag>;
}
