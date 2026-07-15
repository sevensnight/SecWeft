# API、事件与数据兼容策略

## 1. 目的

本策略保证浏览器、CLI、服务、异步消费者和滚动部署实例可以在明确窗口内共存。兼容性是契约、实现和迁移共同属性；仅保留同一路径或让测试编译通过，不代表语义兼容。

P0 的 `1.0.0-p0` 是预发布基线，允许在进入外部试用前修正响应根类型和错误体。首个 `v1` GA 发布后，以下规则成为强制发布门禁。

## 2. 版本面

| 版本面 | 标识 | 权威来源 | 兼容原则 |
|---|---|---|---|
| 外部 REST | URL major `/api/v1` + OpenAPI `info.version` | `packages/api-contracts/openapi/v1.yaml` | 同一 major 只做向后兼容增加 |
| SSE | 路径 major + `event` 名称 + data schema | OpenAPI 与事件 schema | 已发布字段不改语义，新增字段可忽略 |
| 领域事件 | 类型后缀 `.v1` + `schema_version` | `packages/api-contracts/events/` | Producer 先扩展、Consumer 后使用 |
| Tool/Skill/Agent 协议 | `kind` + 语义版本 | `packages/api-contracts/protocol/` | 输入要求不能在 minor 中收紧 |
| 数据库 | 顺序 migration + schema owner | `infrastructure/migrations/` | expand → migrate → contract |
| 前端 SDK | workspace package 版本 | OpenAPI 生成物 | 不手写分叉 DTO |
| 配置 | 变量名 + 配置 schema 版本 | 示例 env/配置 schema | 先支持新旧，再告警，再移除 |

## 3. 兼容和破坏性变更分类

通常兼容：

- 增加非必填响应字段；
- 增加新路径或新 HTTP 操作；
- 增加可选请求字段且默认行为不变；
- 扩大数值上限但不降低安全约束；
- 增加新的稳定错误代码而旧客户端可按状态码处理；
- 新事件类型或已有事件中的可选字段。

属于破坏性变更：

- 删除/重命名字段、路径、枚举值或错误代码；
- 把可选请求字段改为必填，或缩小已承诺的有效范围；
- 改变字段单位、时区、空值、排序、分页或授权语义；
- 把 `200` 成功改成异步 `202` 而不提供迁移版本；
- 修改同名事件含义、重用已发布 event type；
- 将响应数组静默改成对象；
- 删除数据库列时仍有旧实例读写该列。

安全修复可以立即收紧危险行为，但仍需发布说明、稳定错误代码和可审计的拒绝；不能以兼容为由保留权限绕过、外网访问或 secret 回显。

## 4. REST 版本与弃用

同一 major 的弃用至少经历：

1. 新替代接口已经 GA，文档给出迁移映射。
2. 旧接口响应 `Deprecation: true`、`Sunset: <HTTP-date>` 和 `Link: <...>; rel="successor-version"`。
3. 服务记录旧接口调用量，但日志不记录凭据和敏感正文。
4. 覆盖一个约定支持窗口和至少一次客户通知周期。
5. 指标证明无受支持调用方后，才在下一 major 或已公告日期移除。

P0 内部开发接口不因预发布标记获得无限兼容期。每个兼容入口仍必须有退出阶段和责任服务。

## 5. 事件演进

- Event type 永不复用；破坏性 payload 变化发布新后缀，例如 `.v2`。
- Consumer 忽略未知可选字段，拒绝未知 major；不得因新增字段崩溃。
- Producer 在双发布窗口先发布旧/新版本，或发布可被旧消费者接受的扩展版本。
- Consumer 上线并验证后，Producer 才停止旧版本。
- 每条事件携带 `event_id`、`aggregate_version`、tenant/project、trace/correlation/causation；Inbox 对 `event_id` 去重。
- 重放必须使用原 `event_id` 和业务发生时间；不得把重放伪装成新业务动作。
- schema CI 必须包含有效样例、缺字段、未知字段、坏 trace、重复和乱序测试。

## 6. 数据库滚动兼容

数据库变更使用三步法：

1. **Expand**：增加可空列/新表/新索引；旧代码仍能运行。
2. **Migrate**：双读或后台回填并核对数量/hash；保持唯一写真相，避免无边界双写。
3. **Contract**：所有实例和回滚版本停止使用旧结构后，再删除旧列/约束。

每个 migration 有配对的 `.up.sql`/`.down.sql`、锁等待和语句超时、空库验证、已有数据验证、备份恢复说明。含不可逆数据转换时，down 只允许回退应用兼容层并从已验证备份恢复，不能伪造可逆性。

P0 已签入 `0001_p0_enterprise_baseline` 的 up/down 及静态租户安全检查；在真实 PostgreSQL 容器执行空库 up/down 和恢复演练后，运行态数据库兼容才可标记 `Verified`。

## 7. P0 兼容层退出计划

| 现状 | P0 控制 | 替代阶段 | 移除条件 |
|---|---|---|---|
| `X-API-Key` 用户认证 | 仅回环/受控环境，Key 不回显 | P1 OIDC/JWT | OIDC、服务身份、撤销和 MFA 扩展验证通过 |
| SQLite 业务真相 | 保留 characterization tests | P1 PostgreSQL 多租户 repository | 数据核对、RLS/范围负向测试、回滚演练通过 |
| 四个旧角色 | 不作为企业 RBAC 完成证据 | P1 八角色 RBAC+ABAC | 权限矩阵和职责分离测试通过 |
| `/tasks` 原始数组与 `limit` | 预发布只读契约 | P1/P3 游标分页投影 | SDK 和 UI 完成迁移，v1 GA 契约冻结 |
| SQLite 轮询 SSE | 保留 `Last-Event-ID` 语义 | P3 PostgreSQL + NATS fan-out | 重连、缺口、重复、权限撤销测试通过 |
| 旧模型/知识/上下文路由 | 默认权限和审计仍生效 | P2/P4 目标服务 | 独立契约、数据所有权和测试迁移完成 |
| 旧执行/探测/Sandbox 路由 | 默认 `VULNLAB_LEGACY_EXECUTION_ENABLED=false` | P5/P6 受控执行平面 | Linux 隔离、Scope、Policy、Approval、Audit 全部门禁通过后按新契约启用；旧路径不重新开放 |

## 8. P1–P8 兼容工作

- P1：冻结 `v1` 身份、租户、错误体和分页；发布 API Key/SQLite 迁移手册。
- P2：模型 Provider 和流式输出协议版本化；工具调用只接受已注册 schema。
- P3：任务命令、状态和 SSE 稳定；执行多副本、重放、重复和乱序兼容测试。
- P4：知识文档、Chunk、ContextSnapshot 和引用格式版本化；删除/重建保持引用可解释。
- P5：Policy、Approval 和 ExecutionGrant 使用独立版本/digest；旧 grant 不被新执行器接受。
- P6：ValidationPlan、Evidence 和 Review 版本不可变；报告生成器能读受支持旧证据版本。
- P7：前端按生成 SDK 升级，至少支持当前服务版本和上一个受支持 minor。
- P8：在滚动升级、回滚、备份恢复和跨版本事件重放中完成最终兼容验收。

## 9. 发布门禁和检查命令

P0 当前可执行：

```powershell
python -m pytest tests/contract -q -p no:cacheprovider
pnpm --filter @vulnlab/api-contracts test
pnpm generate:api
git diff --exit-code -- packages/shared-types/src/api.generated.ts
docker compose --env-file infrastructure/docker-compose/.env.platform.example -f infrastructure/docker-compose/platform.yml config --quiet
```

GA 发布还必须加入 OpenAPI breaking diff、事件 schema 兼容检查、跨版本 Consumer fixtures、数据库滚动升级/回滚和旧 SDK 端到端测试。缺少其中任一证据时，版本不得标为兼容发布。
