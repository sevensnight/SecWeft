import { Flex, Spin, Typography } from 'antd';

export function LoadingState({ label = '正在加载…' }: { label?: string }) {
  return (
    <Flex vertical align="center" justify="center" gap="middle" className="state-panel">
      <Spin size="large" />
      <Typography.Text type="secondary">{label}</Typography.Text>
    </Flex>
  );
}
