# 模块二 P3：任务与 Agent 编排实现说明

P3 的目标是把旧版单进程任务执行升级为可恢复、可审计、可并发控制的企业级编排内核，同时不引入真实漏洞验证或未授权执行能力。

## 已完成能力

- 持久化 Task/Stage/Execution 状态机。
- Durable queue message、lease token、fencing token、stale lease recovery。
- Idempotency-Key 派发记录和重复提交去重。
- Dead-letter ledger，失败队列消息进入 DLQ，负载写入前脱敏。
- pause/resume/cancel/retry 控制面。
- AgentDefinition、SkillDefinition、WorkflowDefinition 版本化注册表。
- Skill 输入/输出 Schema、权限、资源限制、超时、审批要求和调用统计。
- `/tasks/{id}/events/stream` 继续使用可恢复 SSE。
- OpenAPI 1.3.0-p3：44 个 operation，生成 shared-types。
- PostgreSQL `agent` schema 0006 迁移，启用 FORCE RLS，不授予 DELETE。

## 安全边界

P3 不发布同步 `/run` 企业契约。长任务只能通过 `/tasks/{id}/executions` 入队，再通过查询或 SSE 观察状态。兼容层中的本地 worker 仅用于测试和开发验证。

当前 workflow 限定为 `p3.synthetic.defensive@1.0`，只做范围复核、任务拆解、知识检索占位、已授权非破坏性证据收集、结果分析和防御性报告。P5/P6 之前仍不得启用真实 Sandbox 载荷或漏洞验证执行。

## 验收方式

```powershell
.\.venv\Scripts\python.exe solve_p3_baseline.py
.\.venv\Scripts\python.exe solve_p3_baseline.py --full
```

专项测试覆盖：

- 并发 worker 只有一个能获得有效租约；
- Idempotency-Key 重复派发只产生一条 queue message；
- pause/resume 状态落库；
- stale lease 可恢复为 queued；
- worker 失败进入 DLQ，随后可 retry；
- P3 OpenAPI 44 operations 与运行时投影一致；
- PostgreSQL 0006 migration 具备 tenant-safe FK、RLS 和最小权限。
