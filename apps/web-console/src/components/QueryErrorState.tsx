import { Button, Result } from 'antd';

interface QueryErrorStateProps {
  error: Error;
  onRetry?: () => void;
}

export function QueryErrorState({ error, onRetry }: QueryErrorStateProps) {
  return (
    <Result
      status="warning"
      title="数据加载失败"
      subTitle={error.message}
      extra={onRetry ? <Button onClick={onRetry}>重试</Button> : null}
    />
  );
}
