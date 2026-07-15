import { Empty } from 'antd';

export function EmptyState({ description = '暂无数据' }: { description?: string }) {
  return <Empty className="state-panel" description={description} image={Empty.PRESENTED_IMAGE_SIMPLE} />;
}
