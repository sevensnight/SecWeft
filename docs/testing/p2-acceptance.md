# P2 模型网关验收

## 1. 验收边界

P2 验收模型 Provider、CredentialRef、模型实例元数据、统一调用、结构化输出、工具 allow-list、限流、重试、熔断、failover、usage/cost 和调用账本。

P2 不验收漏洞验证、Sandbox 执行、资产探测、Agent 持久编排或模型生成代码执行。

## 2. 自动验收

```powershell
.\.venv\Scripts\python.exe solve_p2_baseline.py
.\.venv\Scripts\python.exe solve_p2_baseline.py --full
```

`--full` 会运行 Python format/lint/typecheck、P2 Python 测试、workspace typecheck/test/build。

## 3. 必须通过条件

- Provider 响应不得包含 API Key、token、secret 明文。
- Credential 只能以非 secret `credential_ref` 暴露。
- Completion 响应包含 usage、cost、failover_count、latency 和 tool_protocol。
- Invocation ledger 不保存 prompt 或 response 正文。
- 结构化输出必须是 JSON object。
- Token quota 超限必须返回 `429 model_rate_limited`。
- SSE stream 必须使用 `text/event-stream`。
- PostgreSQL `model` schema 表必须启用 FORCE RLS，且不向 `vulnlab_app` 授予 DELETE。

## 4. 手工核对

1. 创建带 `api_key` 的 mock provider，确认响应只有 `has_api_key` 和 `credential_ref`。
2. 调用 `/api/v1/models/complete`，确认返回 usage/cost，但审计和 ledger 中没有 prompt 明文。
3. 使用 `response_format.type=json_object`，确认返回内容可解析为 JSON object。
4. 设置极低 token quota，确认超限返回 429。
5. 调用 `/api/v1/models/stream`，确认先收到 `delta` 事件，最后收到不含完整 content 的 `done` metadata。
