import { Tag } from 'antd';

const COLORS: Record<string, string> = {
  approved: 'blue',
  failed: 'red',
  pending_approval: 'gold',
  running: 'processing',
  succeeded: 'green',
};

export interface StatusPillProps {
  status: string;
}

export function StatusPill({ status }: StatusPillProps) {
  return <Tag color={COLORS[status] ?? 'default'}>{status.replaceAll('_', ' ')}</Tag>;
}
