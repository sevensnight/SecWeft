# P3 任务与 Agent 编排验收

## 1. 自动验收

```powershell
.\.venv\Scripts\python.exe solve_p3_baseline.py
.\.venv\Scripts\python.exe solve_p3_baseline.py --full
```

`--full` 会运行 Python format/lint/typecheck、P3 Python 测试、workspace lint/typecheck/test/build。

## 2. 必须通过条件

- 任务状态、阶段状态、执行记录、队列消息、DLQ 全部持久化。
- 不使用 per-task 内存锁或内存取消标记作为唯一并发控制。
- worker 执行必须带 lease token 和 fencing token。
- 重复派发必须通过 Idempotency-Key 去重。
- stale lease 必须能恢复到 queued。
- 失败 queue message 必须进入 DLQ，DLQ payload 必须脱敏。
- Agent/Skill/Workflow 必须版本化且带 Schema、权限、资源、超时、风险元数据。
- 企业 OpenAPI 不发布同步 `/run`。
- PostgreSQL `agent` schema 必须启用 FORCE RLS，且不向 `vulnlab_app` 授予 DELETE。

## 3. 手工核对

1. 创建并审批一个任务，确认响应包含 `workflow_name` 和 `stages`。
2. 使用相同 `Idempotency-Key` 两次调用 `/tasks/{id}/executions`，确认只有一条 queue message。
3. 调用 `/tasks/{id}/pause` 和 `/tasks/{id}/resume`，确认状态持久变化。
4. 模拟 lease 过期并调用 recovery，确认任务回到 `queued`。
5. 让 worker 阶段失败，确认 `/task-dead-letters` 可看到脱敏记录。
6. 调用 `/agents`、`/workflows`、`/skills`、`/protocols/tools`，确认定义和运行元数据完整。
