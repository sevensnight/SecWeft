# P0 契约与迁移检查工具

本目录只提供确定性、只读检查，不启动容器，也不触发资产探测、沙箱命令或漏洞验证。

```powershell
python tools/contracts/openapi_snapshot.py check --runtime
python tools/contracts/json_schema_check.py
python tools/contracts/check_migrations.py
python solve_p0_baseline.py
```

## OpenAPI 语义快照

快照按解析后的语义文档计算 SHA-256，不受 YAML 注释、缩进和键顺序影响。快照同时锁定操作、参数、响应状态与成功响应媒体类型，因此 SSE 端点必须保持 `text/event-stream`，并声明可恢复消费所需的 `Last-Event-ID` 请求头。

经 API 评审确认属于预期变更后，先查看候选快照：

```powershell
python tools/contracts/openapi_snapshot.py snapshot
```

确认无误后才可更新签入快照：

```powershell
python tools/contracts/openapi_snapshot.py snapshot --write
```

运行时比较是单向兼容检查：签入契约的每个操作都必须存在于 FastAPI 兼容运行时；旧运行时多出的端点不会自动进入 P0 企业契约。

## PostgreSQL 迁移

迁移检查验证以下静态不变量：

- `up` / `down` 成对且各自位于单一显式事务中；
- 回滚按创建顺序的严格逆序删除表，且禁止 `CASCADE`；
- 租户拥有表具备非空 `tenant_id`，跨表外键携带租户维度；
- 可变实体具备 `created_at`、`updated_at` 与乐观锁 `version`；
- Outbox、Inbox、HTTP 幂等、任务事件流索引和审计追加写保护存在；
- 审计事件具备 `trace_id`、`request_id`、任务与主体查询索引。

静态检查不能替代真实 PostgreSQL 环境中的 `up → 查询约束 → down` 集成测试；该项属于后续 CI 数据库服务验证。
