import { zodResolver } from '@hookform/resolvers/zod';
import { Alert, Button, Flex, Input, Modal, Typography } from 'antd';
import { Controller, useForm } from 'react-hook-form';
import { z } from 'zod';

const apiKeySchema = z.object({
  apiKey: z.string().trim().min(1, '请输入 API Key').max(4096, 'API Key 过长'),
});
type ApiKeyForm = z.infer<typeof apiKeySchema>;

interface ApiKeyDialogProps {
  open: boolean;
  onCancel: () => void;
  onClear: () => void;
  onSubmit: (apiKey: string) => void;
}

export function ApiKeyDialog({ open, onCancel, onClear, onSubmit }: ApiKeyDialogProps) {
  const {
    control,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<ApiKeyForm>({ resolver: zodResolver(apiKeySchema), defaultValues: { apiKey: '' } });

  const submit = handleSubmit(({ apiKey }) => {
    onSubmit(apiKey);
    reset();
  });

  return (
    <Modal open={open} title="配置兼容 API Key" onCancel={onCancel} footer={null} destroyOnHidden>
      <Flex component="form" vertical gap="middle" onSubmit={(event) => void submit(event)}>
        <Alert
          showIcon
          type="warning"
          message="密钥只保存在当前页面内存中；刷新即清空，不写入浏览器持久存储。"
        />
        <Controller
          name="apiKey"
          control={control}
          render={({ field }) => (
            <Input.Password
              {...field}
              autoComplete="off"
              aria-label="API Key"
              placeholder="输入 X-API-Key"
              {...(errors.apiKey ? { status: 'error' as const } : {})}
            />
          )}
        />
        {errors.apiKey ? <Typography.Text type="danger">{errors.apiKey.message}</Typography.Text> : null}
        <Flex justify="space-between">
          <Button danger onClick={onClear}>清除当前密钥</Button>
          <Button type="primary" htmlType="submit">应用</Button>
        </Flex>
      </Flex>
    </Modal>
  );
}
