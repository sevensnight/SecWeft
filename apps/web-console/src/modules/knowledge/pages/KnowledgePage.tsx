import { useMutation } from '@tanstack/react-query';
import type { RAGSearchRequest } from '@vulnlab/shared-types';
import { Button, Card, Form, Input, InputNumber, List, Select, Space, Tag, Typography } from 'antd';

import { QueryErrorState } from '../../../components/QueryErrorState';
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
        <Typography.Title level={2}>Knowledge Base</Typography.Title>
        <Typography.Text type="secondary">
          Permission-aware retrieval for CVE notes, internal guidance, task evidence, and historical findings.
        </Typography.Text>
      </div>

      <Card title="Hybrid retrieval">
        <Form<SearchFormValue>
          layout="vertical"
          initialValues={{ query: 'authorized validation evidence', top_k: 5 }}
          onFinish={(value) => {
            const request: RAGSearchRequest = { query: value.query, top_k: value.top_k };
            if (value.classifications?.length) request.classifications = value.classifications;
            search.mutate(request);
          }}
        >
          <Form.Item
            name="query"
            label="Query"
            rules={[{ required: true, min: 2, message: 'Enter at least two characters.' }]}
          >
            <Input.Search enterButton="Search" loading={search.isPending} />
          </Form.Item>
          <Space wrap>
            <Form.Item name="top_k" label="Top K">
              <InputNumber min={1} max={20} />
            </Form.Item>
            <Form.Item name="classifications" label="Classification filter">
              <Select
                mode="multiple"
                allowClear
                className="wide-select"
                options={[
                  { value: 'public', label: 'public' },
                  { value: 'internal', label: 'internal' },
                  { value: 'restricted', label: 'restricted' },
                ]}
              />
            </Form.Item>
            <Form.Item label=" ">
              <Button htmlType="submit" type="primary" loading={search.isPending}>Search</Button>
            </Form.Item>
          </Space>
        </Form>
      </Card>

      {search.isError ? <QueryErrorState error={search.error} onRetry={() => search.reset()} /> : null}
      {search.data ? (
        <Card title={`Results: ${search.data.results.length}`} className="section-gap">
          <List
            dataSource={search.data.results}
            locale={{ emptyText: 'No results' }}
            renderItem={(item) => (
              <List.Item>
                <List.Item.Meta
                  title={<Space><span>{item.title}</span><Tag>{item.classification}</Tag><Tag>{item.trust}</Tag></Space>}
                  description={(
                    <Space direction="vertical" size={2}>
                      <Typography.Paragraph ellipsis={{ rows: 2 }}>{item.excerpt}</Typography.Paragraph>
                      <Typography.Text type="secondary">
                        {item.source}@{item.version} · chunk #{item.chunk_index} · score {item.score.toFixed(3)}
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
