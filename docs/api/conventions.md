# API 设计与实现约定

## 1. 适用范围与当前状态

本文约束外部 REST API、内部同步 API、Server-Sent Events（SSE）和由 OpenAPI 生成的客户端。P0 的权威外部契约是 `packages/api-contracts/openapi/v1.yaml`；事件和领域协议分别以 `packages/api-contracts/events/*.schema.json`、`packages/api-contracts/protocol/*.schema.json` 为准。

P0 当前只把系统状态、任务只读投影和任务事件流纳入签名契约。旧 SQLite/FastAPI 运行时仍保留若干写接口作为迁移兼容层，但这些接口不属于企业 API 完成态；`VULNLAB_LEGACY_EXECUTION_ENABLED=false` 时，旧执行、探测和 Sandbox 路径失败关闭。P1 才落地 OIDC、多租户数据范围和标准错误体，P3 才落地持久化任务命令、NATS 扇出和完整幂等语义。

## 2. API First 工作流

任何对外接口按以下顺序变更，禁止先改路由再补契约：

1. 在 OpenAPI 或 JSON Schema 中描述路径、鉴权、请求、响应、错误和示例。
2. 运行契约解析、语义快照和破坏性变更检查。
3. 生成共享 TypeScript 类型，禁止手写第二套同名 DTO。
4. 实现服务端和客户端；服务实现可以比签名契约多出迁移兼容路径，不能少于签名契约。
5. 补充正常、鉴权失败、数据范围失败、非法状态、重复请求和边界值测试。
6. 在同一变更中提交契约、生成物、实现、测试和兼容说明。

P0 可执行检查：

```powershell
pnpm --filter @vulnlab/api-contracts test
pnpm generate:api
python -m pytest tests/contract/test_openapi_contract.py tests/contract/test_json_schema_contracts.py -q -p no:cacheprovider
git diff --exit-code -- packages/shared-types/src/api.generated.ts
```

最后一条命令要求工作区已初始化 Git；它验证生成结果可重复，不表示整个工作区必须无其他改动。

## 3. 传输、版本和资源命名

- 外部 API 使用 HTTPS；本地开发只允许回环地址上的 HTTP。
- 基础路径使用 `/api/v{major}`。兼容修复和可选字段不改变 URL；破坏性语义升级使用新 major。
- 路径使用小写复数资源名和连字符；数据库表名不直接暴露为 API 名。
- JSON 字段使用 `snake_case`，枚举值使用稳定的大写状态或契约中已声明的小写代码，发布后不得仅因展示偏好改名。
- 资源 ID 是不可推测的 UUID；时间是带时区的 RFC 3339 UTC，例如 `2026-07-11T08:30:00Z`。
- 金额、配额和计数不使用二进制浮点表达精确值；字节大小以整数表示。
- `GET`、`HEAD` 无副作用；创建使用 `POST`，整体替换使用 `PUT`，部分更新使用 `PATCH`，删除语义优先使用归档/撤销命令。
- 业务命令可使用 `POST /tasks/{id}:cancel` 一类显式命令，但同一领域必须统一；现有 `/tasks/{id}/cancel` 是 P0 兼容形态。

P0 OpenAPI 版本 `1.0.0-p0` 是预发布契约，不对外承诺 GA 稳定性。发布 `v1` GA 后必须遵守 [兼容策略](compatibility.md)。

## 4. 身份、数据范围与权限

P0 的 `X-API-Key` 仅用于旧原型兼容，Key 不得出现在 URL、SSE 查询参数、日志或前端持久化存储。P1 外部接口统一采用 OIDC Authorization Code + PKCE 或受信服务的 Client Credentials，HTTP 头为 `Authorization: Bearer <token>`。

租户和项目范围从已验证的身份、成员关系与目标资源推导。客户端传入的 `tenant_id`、`project_id` 只是资源选择条件，不是授权证明。后端和异步消费者都必须执行：

```text
认证 → tenant/project 数据范围 → RBAC → ABAC/Policy → 资源状态 → 审计
```

为避免资源枚举，主体对资源无数据范围权限时通常返回 `404`；主体能看到资源但缺少动作权限时返回 `403`。前端隐藏菜单或按钮不构成授权控制。

## 5. 请求关联、追踪与审计

- 客户端可传 UUID 格式的 `X-Request-ID`；缺失时 Gateway 生成并在响应回传。
- 服务间传播 W3C `traceparent`/`tracestate`，业务事件同时携带 `trace_id`、`correlation_id` 和 `causation_id`。
- 响应、日志、策略决定和审计事件使用同一 request/trace 关联信息。
- 外部提供的 request ID 只作关联，不直接作为数据库主键、幂等键或授权值。
- 日志只记录字段白名单；请求正文、认证头、模型 Key、ExecutionGrant 和原始证据默认不记录。

## 6. 幂等与并发控制

所有可能重复产生副作用的创建、提交、审批、取消、重试、导出和执行命令都必须支持 `Idempotency-Key`。目标实现规则如下：

1. Key 为 16–200 个可打印 ASCII 字符，不接受空白、secret 或业务正文。
2. 唯一范围为 `tenant_id + project_id(可空) + operation + key`。
3. 服务保存规范化请求体的 SHA-256、处理状态、响应状态、响应体或资源引用及过期时间。
4. 相同 Key 与相同请求 hash 返回第一次完成的结果，不重复产生 Task、Approval、Run、Evidence 或 Outbox。
5. 相同 Key 与不同请求 hash 返回 `409 idempotency_key_reused`。
6. 处理中重复请求返回原资源状态；不能安全复用时返回 `409 request_in_progress` 和有限的 `Retry-After`。
7. 幂等记录至少覆盖客户端最大重试窗口；高风险执行 nonce 在审计保留期内不可复用。

P0 PostgreSQL 迁移已定义 `control.idempotency_records`、按租户/项目的唯一索引以及过期字段；旧兼容写 API 尚未全面接入，因此不能把数据库表存在表述为幂等能力已验证。接入在 P1/P3 完成。

可变聚合使用 `version` 乐观锁。命令体携带 `expected_version`，条件更新失败返回 `409 version_conflict`；不得用最后写入覆盖审批、Task 状态、Evidence 或审计历史。状态迁移、领域事件和 Outbox 必须在一个本地事务中提交。

## 7. 查询、过滤、排序和分页

目标集合响应采用游标分页：

```json
{
  "items": [],
  "page": {
    "next_cursor": null,
    "has_more": false,
    "page_size": 50
  }
}
```

- 参数为 `page_size` 和 `cursor`，默认 50、最大 100；服务可以对日志/事件采用更小上限。
- Cursor 是不透明、带签名或服务端可验证的值，绑定租户、过滤器、排序和稳定的末项键。
- 默认排序必须确定，例如 `created_at DESC, id DESC`；客户端不得推断 cursor 内容。
- 过滤字段和排序字段必须在 OpenAPI 白名单中声明；未知字段返回 `422`，不拼接原始 SQL。
- 总数计算昂贵时不返回 `total`；确有业务需要时显式请求近似或异步统计。

P0 `/tasks` 仍返回原始数组并使用 `limit`（1–500，默认 100），这是签名预发布契约中的迁移例外。P1 在 v1 GA 前改成标准分页；若 v1 已对外 GA，则通过新版本迁移而不是静默改变响应根类型。

## 8. 错误协议

目标错误响应使用 `application/problem+json`，结构稳定且不泄漏内部异常：

```json
{
  "type": "https://errors.vulnlab.example/invalid-state-transition",
  "title": "Invalid state transition",
  "status": 409,
  "code": "invalid_state_transition",
  "detail": "Task cannot move from RUNNING to SUBMITTED",
  "instance": "/api/v1/tasks/…",
  "request_id": "…",
  "errors": []
}
```

`code` 是客户端分支依据，`detail` 仅供人阅读。字段校验错误的 `errors` 只包含安全的字段路径、规则代码和简短消息，不回显 secret 或完整输入。

| HTTP | 语义 | 典型稳定代码 |
|---:|---|---|
| 400 | 无法解析的请求 | `invalid_request` |
| 401 | 未认证或凭据失效 | `authentication_required` |
| 403 | 已认证但动作被拒绝 | `permission_denied`、`policy_denied` |
| 404 | 不存在或不在数据范围 | `resource_not_found` |
| 409 | 状态、版本、幂等冲突 | `invalid_state_transition`、`version_conflict` |
| 412 | 条件请求失败 | `precondition_failed` |
| 422 | 结构正确但字段/Scope 无效 | `validation_failed`、`scope_violation` |
| 429 | 限流/配额 | `rate_limited`、`quota_exceeded` |
| 503 | 依赖不可用或安全失败关闭 | `dependency_unavailable`、`audit_unavailable` |

P0 兼容运行时当前返回 `{detail, code?, request_id?}` 的 `application/json`，且部分框架校验错误仍使用 FastAPI 默认结构。该差异必须留在兼容说明中，P1 统一错误中间件和 OpenAPI schema 后才标记 `Verified`。

## 9. SSE 事件流

任务事件订阅路径是 `GET /api/v1/tasks/{task_id}/events/stream`，响应 `text/event-stream`。协议要求：

```text
id: 184
event: task-event
data: {"id":184,"event_type":"task.state_changed","payload":{},"created_at":"…"}

```

- 每条业务事件包含单调 `id`；客户端重连用 `Last-Event-ID` 头续传，不把凭据放查询参数。
- 服务定期发送 `: keepalive` 注释；代理必须关闭缓冲，响应设置 `Cache-Control: no-cache, no-transform`。
- 数据必须是单行、有效 JSON，不含 secret；超大日志和证据只发送 URI/hash/摘要。
- 客户端按指数退避重连并加入抖动；收到重复 ID 时去重，发现缺口时调用持久事件列表补齐。
- `401/403/404` 在建立流之前返回普通错误；权限撤销后服务应终止现有流。
- P0 实现以持久 SQLite 事件表轮询提供兼容流；P3 改为 PostgreSQL 真相源加 NATS 扇出，但保持 SSE 外部语义和 `Last-Event-ID` 恢复能力。

## 10. 输入、输出与安全限制

- 服务端 schema 默认拒绝未知字段，长度、数量、枚举、数值和嵌套深度均设上限。
- URL、主机、IP、端口、重定向和代理在实际连接点重新做 Authorization Scope 校验。
- 上传采用媒体类型、大小、hash、恶意内容扫描和对象存储隔离；API 不接受任意本地路径。
- Tool/Skill 调用只接受注册版本和类型化参数，不接受 Shell 字符串。
- 响应不可包含 secret 明文、内部堆栈、数据库 SQL、容器路径、ExecutionGrant 或其他租户标识。
- 高风险写操作若审计 Outbox 无法持久化则失败关闭。

## 11. 契约完成定义

一次 API 变更只有同时满足以下条件才是完成态：契约可解析、生成物无漂移、服务实现存在、正常和负向测试通过、权限和数据范围明确、日志脱敏、幂等/并发语义明确、兼容性分类完成、文档示例可执行。P0 只对签名只读路径满足这一定义；其余旧路由保持 `Legacy Implemented/Legacy Verified` 标签。
