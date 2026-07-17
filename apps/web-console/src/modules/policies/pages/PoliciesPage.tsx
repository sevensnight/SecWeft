import { useMutation, useQuery } from '@tanstack/react-query';
import type { PolicyEvaluationRequest } from '@vulnlab/shared-types';
import { Alert, Button, Card, Form, Input, InputNumber, List, Select, Space, Switch, Tag, Typography } from 'antd';

import { QueryErrorState } from '../../../components/QueryErrorState';
import { evaluatePolicy, listAuditEvents } from '../../../services/api';

interface PolicyFormValue {
  action: PolicyEvaluationRequest['action'];
  destructive: boolean;
  port?: number;
  reason?: string;
  target?: string;
}

export function PoliciesPage() {
  const audit = useQuery({
    queryKey: ['audit', 'policy', 'recent'],
    queryFn: () => listAuditEvents(50),
    staleTime: 10_000,
  });
  const evaluation = useMutation({
    mutationFn: (value: PolicyEvaluationRequest) => evaluatePolicy(value),
  });

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>策略审批</Typography.Title>
        <Typography.Text type="secondary">
          手工预评估策略命中结果；真正执行仍必须由后端 PEP、Scope 和审批状态再次校验。
        </Typography.Text>
      </div>

      <Alert
        showIcon
        type="warning"
        message="策略判定不授予执行能力"
        description="本页面只产生可审计的 policy_decision。批准验证计划或 allow 决策都不会绕过后端执行边界。"
      />

      <Card title="策略预评估" className="section-gap">
        <Form<PolicyFormValue>
          layout="vertical"
          initialValues={{ action: 'asset.probe', destructive: false, target: 'tcp://127.0.0.1:65534', port: 65534 }}
          onFinish={(value) => {
            evaluation.mutate({
              action: value.action,
              resource_type: 'frontend_preflight',
              resource_id: 'manual',
              target: value.target || null,
              ports: value.port ? [value.port] : [],
              destructive: value.destructive,
              reason: value.reason || null,
              metadata: { source: 'web-console' },
            });
          }}
        >
          <Space wrap align="start">
            <Form.Item name="action" label="动作">
              <Select
                className="wide-select"
                options={[
                  { value: 'asset.probe', label: 'asset.probe' },
                  { value: 'sandbox.run', label: 'sandbox.run' },
                  { value: 'task.execute', label: 'task.execute' },
                  { value: 'context.restore', label: 'context.restore' },
                  { value: 'rag.search', label: 'rag.search' },
                ]}
              />
            </Form.Item>
            <Form.Item name="target" label="目标">
              <Input className="wide-input" />
            </Form.Item>
            <Form.Item name="port" label="端口">
              <InputNumber min={1} max={65535} />
            </Form.Item>
            <Form.Item name="destructive" label="破坏性" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="reason" label="原因">
              <Input className="wide-input" />
            </Form.Item>
            <Form.Item label=" ">
              <Button type="primary" htmlType="submit" loading={evaluation.isPending}>评估</Button>
            </Form.Item>
          </Space>
        </Form>
      </Card>

      {evaluation.isError ? <QueryErrorState error={evaluation.error} onRetry={() => evaluation.reset()} /> : null}
      {evaluation.data ? (
        <Card title="策略结果" className="section-gap">
          <Space direction="vertical">
            <Space>
              <Tag color={evaluation.data.decision === 'allow' ? 'green' : 'red'}>{evaluation.data.decision}</Tag>
              <Typography.Text>{evaluation.data.reason}</Typography.Text>
            </Space>
            <Typography.Text code copyable>{evaluation.data.policy_hash}</Typography.Text>
          </Space>
        </Card>
      ) : null}

      <Card title="近期策略审计" className="section-gap" loading={audit.isPending}>
        <List
          dataSource={(audit.data ?? []).filter((item) => item.action.startsWith('policy.')).slice(0, 12)}
          locale={{ emptyText: '暂无策略审计事件' }}
          renderItem={(item) => (
            <List.Item extra={<Tag>{item.outcome}</Tag>}>
              <List.Item.Meta
                title={item.action}
                description={`${item.resource_type}:${item.resource_id} · ${new Date(item.occurred_at).toLocaleString()}`}
              />
            </List.Item>
          )}
        />
      </Card>
    </section>
  );
}
