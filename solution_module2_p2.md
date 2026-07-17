# 模块二 P2 题解：模型网关

## 1. 问题分析

P2 的核心不是“把某个厂商 SDK 接进来”，而是建立统一、可审计、可限流、可失败切换的模型调用边界。业务代码只能面对 Provider/Model/CredentialRef 抽象，不能直接依赖厂商 SDK，也不能把 API Key、prompt、response body 写入审计或调用账本。

本阶段仍不启用漏洞验证、资产探测、Sandbox 或模型生成代码执行。模型输出只作为分析文本或结构化对象返回，不作为漏洞验证成功证据。

## 2. 架构方案

模型网关由四层组成：

1. Provider 元数据：类型、endpoint、模型名、能力标签、优先级、限流和成本参数。
2. CredentialRef：响应只返回 `credential://provider/{id}/api-key` 这类非 secret 引用；明文只在写入或轮换请求中出现。
3. 调用执行器：统一注入安全 system policy，执行 request/minute、token/minute、retry、circuit breaker 和 failover。
4. 调用账本：只记录 request hash、usage、cost、状态、延迟、failover 次数和工具数量，不记录 prompt/response 正文。

兼容运行时继续支持 `mock`、`openai_compatible` 和 `ollama`。真实企业 PostgreSQL 侧新增 `model` schema，包含 `credentials`、`providers`、`instances` 和 `invocations`，全部启用 FORCE RLS。

## 3. 关键算法

- Token 估算：按消息字符长度近似估算 prompt/completion token，用于本地 quota 和成本单测。
- 成本计算：`prompt_tokens / 1000 * input_cost_per_1k + completion_tokens / 1000 * output_cost_per_1k`。
- 限流：先检查 provider request/minute，再检查 actor/provider token/minute。
- 重试：provider 内按 `config.max_retries` 限制，最大 3 次。
- 熔断：同一 provider 连续失败达到阈值后短期开路，health API 暴露 circuit 状态。
- Failover：按 enabled provider 的 priority 排序，主 provider 失败后尝试后备 provider。
- 结构化输出：`response_format.type=json_object` 时要求 provider 返回 JSON object。
- 工具协议：请求工具以 allow-list 形式传入，返回中明确 `allowed_tools`，模型不得自行扩展未注册工具。

## 4. 复杂度

设 provider 数为 `P`、每个 provider 最大重试数为 `R`、输入长度为 `L`、输出长度为 `O`：

- 路由与失败切换：最坏 `O(P * R)` 次 provider 尝试。
- Token 估算：`O(L + O)`。
- 账本写入：单次 `O(1)`。
- Health/catalog 查询：`O(P)`。

## 5. 验收

核心入口：

```powershell
.\.venv\Scripts\python.exe solve_p2_baseline.py
.\.venv\Scripts\python.exe solve_p2_baseline.py --full
```

专项测试覆盖：

- secret 不回显；
- 结构化 JSON 输出；
- 工具 allow-list；
- usage/cost 统计；
- invocation ledger 不含 prompt/response body；
- token quota 触发 429；
- SSE streaming；
- P2 OpenAPI 28 operations；
- PostgreSQL 0005 migration 的 RLS、CredentialRef 和最小权限。
