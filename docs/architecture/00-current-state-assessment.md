# 当前状态评估与演进基线

## 1. 结论

当前仓库是一个可运行、可测试的单节点授权靶场原型，不是企业级目标系统。它证明了若干安全算法和端到端概念，但没有建立多租户、服务隔离、分布式状态、企业身份、API First、前端和生产部署基线。

因此采用“保留安全算法与测试、重建企业边界、逐上下文提取”的演进策略。禁止以目录重命名代替服务拆分，也禁止为了追求微服务外观一次性重写全部可用代码。

## 2. 已核实事实

| 事实 | 代码或配置证据 | 状态 | 企业影响 |
|---|---|---|---|
| 单个 FastAPI 应用承载主要 API | `src/vulnlab/app.py` | Legacy Implemented | 路由、鉴权和业务逻辑边界过于集中 |
| SQLite 是业务状态真相源 | `src/vulnlab/db.py`、`.env.example` | Legacy Verified | 不支持目标多副本写入、租户 RLS 和规范迁移 |
| 核心表没有统一 `tenant_id/project_id/version` | `src/vulnlab/db.py` | Legacy Implemented | 无法证明租户隔离和并发覆盖防护 |
| RBAC 只有四个硬编码角色 | `src/vulnlab/security.py` | Legacy Verified | 不满足八类企业角色、数据范围与职责分离模型 |
| API Key 是主要用户身份 | `src/vulnlab/security.py`、`src/vulnlab/app.py` | Legacy Verified | 缺少 OIDC、JWT 生命周期、组织成员与 MFA 扩展 |
| 任务锁和并发控制包含进程内状态 | `src/vulnlab/orchestrator.py`、`src/vulnlab/db.py` | Legacy Verified | 多 worker/多副本下不能作为唯一并发控制 |
| OpenAPI 由运行时框架生成 | `src/vulnlab/app.py` | Legacy Implemented | 不符合“契约先行、生成服务端和前端类型” |
| Compose 只有 API 与合成靶场 | `docker-compose.yml` | Legacy Verified | 缺少 PostgreSQL、消息、缓存、对象存储和可观测性 |
| 没有企业 Web Console | 仓库无 `apps/web-console` | Planned | 无法验收前端模块、性能和权限裁剪 |
| 没有独立 migration 目录或迁移工具 | `src/vulnlab/db.py` 内嵌 schema/migration | Legacy Implemented | 无法按服务管理可回滚数据库变更 |
| 审计链与业务状态位于同一 SQLite 文件 | `src/vulnlab/audit.py`、`src/vulnlab/db.py` | Legacy Verified | 管理数据库和主密钥的攻击者可整体替换链 |
| 当前目录没有 Git 元数据 | 项目根目录无 `.git` | Planned | 无法形成可回滚、可审计的增量提交 |

“Legacy Verified”仅表示旧测试曾在旧边界内运行，不代表目标架构已验证。

## 3. 可复用资产

| 原型模块 | 可复用的设计/测试 | 目标去向 | 迁移限制 |
|---|---|---|---|
| `scope.py` | 目标规范化、白名单、端口交集、DNS/IP 重验 | `asset-service` 的领域规则与安全解析器 | 需要加入 tenant/project、授权文档、时间窗和策略版本 |
| `audit.py` | 递归脱敏、规范 JSON、HMAC hash chain | `audit-service` | 需要独立存储权限、外部 WORM 锚定和事件消费 |
| `model_gateway.py` | Provider Adapter、限流、熔断、failover | `model-gateway` | 凭据改为 secret reference，增加租户配额和持久统计 |
| `orchestrator.py` | 有界 DAG、状态迁移、取消、重试思路 | `control-plane` 与 `agent-orchestrator` | Task 真相归 control-plane，锁改为租约/版本/fencing token |
| `sandbox.py` | 类型化 argv、默认 dry-run、容器资源限制 | `sandbox-service` | 生产执行必须迁移到独立 Linux worker，不挂 Docker Socket |
| `context.py` | 写入前清洗、checkpoint、安全信封 | `context-service` | 授权真相必须从 control-plane/asset-service 重取 |
| `rag.py` | ACL 前置过滤、来源/hash | `knowledge-service` | 加版本化文档、chunk、混合检索和项目 ACL |
| `security.py` | API Key HMAC、递归 secret 清洗 | 共享安全库/服务认证兼容层 | 用户认证改为 OIDC；移除 `admin=*` 权限模型 |
| `tests/` | 安全不变量和端到端 characterization | 对应服务测试与顶层回归 | 迁移后必须在 PostgreSQL、消息和多租户条件下重跑 |

## 4. 结构性差距

### 4.1 身份与数据隔离

- 缺少 Tenant、Organization、Project、Membership、RoleAssignment。
- 缺少数据库级 RLS 与统一 repository scope。
- 缓存、事件、对象存储 key 尚未定义租户命名空间。
- 平台管理员当前是通配权限，不符合最小权限和业务内容隔离。

### 4.2 任务与分布式一致性

- Task、Stage、Execution Attempt 和 Approval 状态未充分分离。
- 没有 durable queue、outbox/inbox、幂等事件和死信队列。
- 进程内锁不能防止多副本并发副作用。
- 暂停、恢复、取消和补偿尚无租约、fencing 和 worker 丢失协议。

### 4.3 服务和数据所有权

- 当前所有表位于同一 schema，模块可以直接访问任意表。
- API 层包含领域判断，无法独立测试或替换 transport。
- 任务、模型、知识、上下文、沙箱和审计尚无独立契约。

### 4.4 工程与交付

- 没有 pnpm workspace/Turborepo、前端构建、Storybook、Playwright。
- 没有静态 OpenAPI、事件 Schema、生成 SDK 和契约兼容检查。
- 没有 CI、安全扫描、SBOM、镜像签名和发布审批。
- 没有 Kubernetes/Helm、监控告警、备份恢复和迁移演练。

## 5. 演进路线

1. P0 固化事实、设计、契约、目录和基础设施，不实现漏洞验证。
2. 保留旧原型测试作为 characterization tests，迁移一项验证一项。
3. P1 首先建立身份、租户、项目、RBAC、配置和审计；后续服务不得绕过。
4. PostgreSQL 初期可共用集群，但按服务 schema 和账号隔离；禁止跨 schema 查询。
5. 使用 transactional outbox/inbox 避免一开始引入分布式事务。
6. 先以 PostgreSQL FTS + pgvector 支持 MVP 检索；只有容量和查询证据支持时才增加 OpenSearch。
7. P5 之前 Sandbox 保持不可执行或仅运行固定健康检查；P6 才允许合成靶场的非破坏性验证。
8. 旧单节点入口只作为过渡兼容层，不作为最终生产部署单元。

## 6. P0 安全边界

P0 明确不包含：

- 真实漏洞 payload、EXP 或武器化 PoC。
- 对公网或未知目标的扫描、探测和验证。
- 任意命令、任意代码、宿主机或 Docker Socket 执行。
- 持久化、横向移动、凭据访问、破坏、拒绝服务、绕过审计或规避防护。
- 宣称普通容器能够提供绝对防逃逸能力。

P0 允许的可执行 smoke 仅包括：服务健康检查、数据库迁移、消息发布消费、对象存储读写、固定无副作用命令和合成事件链。

## 7. 完成定义

本评估只有在以下条件满足后才可标记 `Verified`：

- 每项事实都能定位到文件、配置或实际命令输出。
- 旧原型和目标架构的状态标签没有混用。
- 能力矩阵中的每项需求都有目标服务、阶段和验收证据类型。
- 风险登记册覆盖本文件列出的结构性差距。
- P0 验收明确禁止漏洞验证能力进入构建或 smoke。
