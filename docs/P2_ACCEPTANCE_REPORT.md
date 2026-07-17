# P2 模型网关验收报告

记录日期：2026-07-17（Asia/Shanghai）。

## 1. 结论

Accepted。

P2 已实现模型网关的 Provider/Model/CredentialRef、结构化输出、工具 allow-list、请求与 token 限流、重试、熔断、failover、usage/cost、provider health、SSE stream 和调用账本。当前提交不启用漏洞验证、资产探测、Sandbox 或模型生成代码执行。

## 2. 实现证据

| 范围 | 主要证据 |
|---|---|
| Provider/Model | `model_gateway.py`、`/providers`、`/models/catalog`、P2 OpenAPI |
| CredentialRef | provider 响应只返回 `credential_ref`，secret 写入后不回显 |
| 调用执行 | `/models/complete`、`/models/stream`、mock/openai-compatible/ollama adapter |
| 限流/熔断 | request/minute、token/minute、retry、circuit breaker、`/providers/health` |
| usage/cost | completion 响应和 invocation ledger 记录 token 与成本 |
| 工具协议 | `tools[]` allow-list 与 `tool_protocol.allowed_tools` |
| 数据库 | `0005_p2_model_gateway` 创建 `model` schema、RLS、最小权限和账本 |
| 测试 | `tests/test_api.py`、OpenAPI contract、migration contract、`solve_p2_baseline.py` |

## 3. 最终结果

本次本地复跑结果：

| 门禁 | 结果 |
|---|---|
| `solve_p2_baseline.py` | PASS，5/5 |
| `solve_p2_baseline.py --full` | PASS，13/13 |
| 全量 `pytest -o addopts=''` | PASS，89 passed，1 skipped |
| P2 API 行为测试 | PASS，20 tests in `tests/test_api.py` |
| OpenAPI contract/runtime projection | PASS，28 operations |
| PostgreSQL migration static check | PASS，0001-0005 |
| P2 migration safety assertions | PASS |
| Ruff format/check | PASS，67 files formatted / All checks passed |
| mypy | PASS，39 source files |
| workspace typecheck/test/build | PASS，6 packages |
| Web bundle budget | PASS，17 assets，541260 gzip bytes |

## 4. 明确限制

- P2 不把模型输出当作漏洞验证成功证据。
- P2 不执行工具、命令、PoC 或网络探测。
- 真实外部 Provider 契约需要显式配置 isolated/test endpoint 后再验收；默认只使用 deterministic mock。
- P3 才接入持久 Agent/Task 编排；P5/P6 之前不得进入 Sandbox 或漏洞验证执行面。
