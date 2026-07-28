import { useMutation } from '@tanstack/react-query';
import type { RAGSearchRequest } from '@vulnlab/shared-types';
import { Button, Card, Form, Input, InputNumber, List, Select, Space, Tag, Typography } from 'antd';

import { QueryErrorState } from '../../../components/QueryErrorState';
import { cnLabel } from '../../../i18n/formatters';
import { searchRagDocuments } from '../../../services/api';

interface SearchFormValue {
  classifications?: ('public' | 'internal' | 'restricted')[];
  query: string;
  top_k: number;
}

export function KnowledgePage() {
  const search = useMutation({
    mutationFn: (value: RAGSearchRequest) => searchRagDocuments(value),
  });

  return (
    <section>
      <div className="page-title-row">
        <Typography.Title level={2}>知识库</Typography.Title>
        <Typography.Text type="secondary">
          面向 CVE 记录、内部指引、任务证据和历史发现的权限感知检索。
        </Typography.Text>
      </div>

      <Card title="混合检索">
        <Form<SearchFormValue>
          layout="vertical"
          initialValues={{ query: '授权验证证据', top_k: 5 }}
          onFinish={(value) => {
            const request: RAGSearchRequest = { query: value.query, top_k: value.top_k };
            if (value.classifications?.length) request.classifications = value.classifications;
            search.mutate(request);
          }}
        >
          <Form.Item
            name="query"
            label="查询内容"
            rules={[{ required: true, min: 2, message: '请输入至少两个字符。' }]}
          >
            <Input.Search enterButton="搜索" loading={search.isPending} />
          </Form.Item>
          <Space wrap>
            <Form.Item name="top_k" label="返回条数">
              <InputNumber min={1} max={20} />
            </Form.Item>
            <Form.Item name="classifications" label="密级过滤">
              <Select
                mode="multiple"
                allowClear
                className="wide-select"
                options={[
                  { value: 'public', label: '公开' },
                  { value: 'internal', label: '内部' },
                  { value: 'restricted', label: '受限' },
                ]}
              />
            </Form.Item>
            <Form.Item label=" ">
              <Button htmlType="submit" type="primary" loading={search.isPending}>搜索</Button>
            </Form.Item>
          </Space>
        </Form>
      </Card>

      {search.isError ? <QueryErrorState error={search.error} onRetry={() => search.reset()} /> : null}
      {search.data ? (
        <Card title={`检索结果：${search.data.results.length}`} className="section-gap">
          <List
            dataSource={search.data.results}
            locale={{ emptyText: '暂无结果' }}
            renderItem={(item) => (
              <List.Item>
                <List.Item.Meta
                  title={<Space><span>{item.title}</span><Tag>{cnLabel(item.classification)}</Tag><Tag>{cnLabel(item.trust)}</Tag></Space>}
                  description={(
                    <Space direction="vertical" size={2}>
                      <Typography.Paragraph ellipsis={{ rows: 2 }}>{item.excerpt}</Typography.Paragraph>
                      <Typography.Text type="secondary">
                        {item.source}@{item.version} · 分片 #{item.chunk_index} · 得分 {item.score.toFixed(3)}
                      </Typography.Text>
                      <Typography.Text code copyable>{item.citation.chunk_hash}</Typography.Text>
                    </Space>
                  )}
                />
              </List.Item>
            )}
          />
        </Card>
      ) : null}
    </section>
  );
}
