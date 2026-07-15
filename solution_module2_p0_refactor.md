# 模块二 P0 架构与工程基线重构题解

> 最终状态：**P0 Accepted（本地工程基线）**。本阶段没有实现或开启具体漏洞验证能力；P1–P8 仍按里程碑推进。

## 1. 本次完成目标

本次先审查旧的单节点 FastAPI/SQLite 原型，再以演进式方式建立企业工程底座，避免把兼容实现误报为目标架构。完成了需求矩阵、服务边界、数据流、领域/ER、状态机、八角色权限、策略审批、风险和 ADR，并把这些设计落实为 Monorepo、API First 契约、模块化控制面、企业前端壳层、可逆 PostgreSQL migration、Compose/Helm、可观测性、备份恢复、CI 和可执行验收器。

验收器 [`solve_p0_baseline.py`](solve_p0_baseline.py) 将目录、安全默认值、Git、OpenAPI、JSON Schema、migration、Compose、Python 和 pnpm 门禁统一为机器可读结果。完整证据见 [`docs/P0_ACCEPTANCE_REPORT.md`](docs/P0_ACCEPTANCE_REPORT.md)。

## 2. 架构和实现说明

### 2.1 演进边界

- `apps/control-plane` 保留旧 API 的行为回归入口，但已拆为配置、依赖、服务、序列化、运行时和路由模块；遗留执行默认关闭。
- `packages/api-contracts` 是 OpenAPI、任务事件和领域协议的唯一权威源；TypeScript DTO 自动生成，禁止重复手写。
- `apps/web-console` 建立 React/TypeScript/Vite 企业壳层，按路由与重依赖分包；任务列表虚拟化，SSE 增量消费，过滤交给 Web Worker。
- PostgreSQL、Redis、NATS JetStream、MinIO、OTel 和 Prometheus 组成 P0 平台基线；兼容控制面尚未把 SQLite 切换为 PostgreSQL 真相源。
- Keycloak 只作为默认关闭的 `identity` profile，为 P1 Authorization Code + PKCE/JWKS 集成提供前置条件。
- Kubernetes/Helm 是可 lint、可渲染的部署预留，不被表述为 P8 生产交付。

### 2.2 自动检查方法

1. 检查 P0 必需文件、文档和安全默认值；
2. 解析 OpenAPI 3.1，锁定 5 个只读操作、参数、媒体类型和语义摘要；
3. 对隔离 FastAPI 实例核对运行时路由和 SSE `Last-Event-ID`；
4. 用 JSON Schema 2020-12 校验事件和领域协议；
5. 检查 migration 的 up/down 对称、严格逆序回滚、租户复合外键、幂等/Outbox/Inbox 和追加审计约束；
6. 解析 Compose 模型；完整模式再执行 Python 与前端全量门禁；
7. 在真实容器中验证健康、OIDC 元数据、数据库约束、备份恢复和运维脚本；
8. 用 Git、锁文件 hash、secret/依赖扫描和 CI 配置建立可追溯性。

静态扫描对输入规模近似线性；规范化 OpenAPI 排序摘要的上界为 `O(C log C)`。完整验收耗时主要由依赖扫描、pytest、TypeScript/Vite 和容器生命周期决定。

## 3. 新增或修改的文件

主要交付分组如下：

- 架构与治理：`docs/architecture`、`docs/security`、`docs/adr`、`docs/engineering`；
- API 与共享包：`packages/api-contracts`、`packages/shared-types`、`packages/api-client`、`packages/config`、`packages/ui-components`；
- 应用：`apps/api-gateway`、`apps/control-plane`、`apps/web-console`；
- 数据与部署：`infrastructure/migrations`、`infrastructure/docker-compose`、`infrastructure/keycloak`、`infrastructure/monitoring`、`infrastructure/kubernetes/helm`、`infrastructure/scripts`；
- 质量与交付：`tests`、`tools/contracts`、`.github/workflows/ci.yml`、`Makefile`、`Taskfile.yml`、各类 lockfile；
- 解题与验收：`solve_p0_baseline.py`、本文件和 `docs/P0_ACCEPTANCE_REPORT.md`。

未提交 `.env.platform`、数据库、构建目录、浏览器报告、备份和本地工具。

## 4. 数据库变更

`0001_p0_enterprise_baseline` 在 `iam`、`control`、`audit` 三个 Schema 中创建 15 张表。核心设计包括：

- 所有租户拥有实体携带非空 `tenant_id`，跨表引用使用带租户键的复合外键；
- 核心可变表包含创建/更新时间和 `version`，为乐观并发控制预留；
- Outbox、Inbox 和 HTTP idempotency 记录具有明确去重键；
- 审计事件由数据库触发器拒绝 UPDATE/DELETE；
- down migration 不使用 `CASCADE`，按依赖严格逆序删除，可回滚。

真实 PostgreSQL 已执行 `up → down → up`。最终查询得到 15 张表、18 个复合租户外键和 1 个追加写保护触发器；事务负向测试证明跨租户 task 外键和审计更新均被拒绝。随后完成备份、校验与恢复，恢复后再次核对 15 张表。

## 5. API 变更

P0 企业契约只包含以下查询操作：

- `GET /api/v1/system/requirements`
- `GET /api/v1/tasks`
- `GET /api/v1/tasks/{task_id}`
- `GET /api/v1/tasks/{task_id}/events`
- `GET /api/v1/tasks/{task_id}/events/stream`

SSE 固定返回 `text/event-stream`，支持非负整数 `Last-Event-ID` 断点续传、持久事件游标与 keepalive。契约测试阻止媒体类型退化和运行时漂移。遗留 `/run`、资产探测和沙箱执行端点未进入 P0 企业 OpenAPI，并在默认配置下 fail closed。

## 6. 配置变更

- `VULNLAB_EXECUTION_MODE=dry_run`；
- `VULNLAB_LEGACY_EXECUTION_ENABLED=false`；
- 所有平台 secret 必须从忽略提交的 `.env.platform` 注入，启动脚本拒绝占位符、短口令和非法 Fernet Key；
- 基础数据服务只加入内部网络；Keycloak、MinIO Console 和 Prometheus 仅回环暴露管理端口；
- 容器使用非 root、只读根文件系统、capability 收缩、资源/健康限制；备份/恢复工具只获完成卷读取或恢复所需的最小 capability；
- Python 生产依赖使用带 hash 的锁文件；pnpm 使用 frozen lockfile；
- 本机 8080 已被无关项目占用，因此本次通过 `PLATFORM_GATEWAY_PORT=18080` 验证。

## 7. 安全影响

- 默认拒绝遗留执行，P0 验收脚本本身不启动探测、不执行载荷、不访问目标；
- API Key 只经请求头传递，前端仅保存在内存，不进入 URL、localStorage 或日志；
- 网关设置 CSP 等安全响应头，未认证任务接口返回 401；
- 多租户复合外键、幂等键和追加审计约束降低跨租户误关联、重复副作用和审计篡改风险；
- OIDC、八角色、Policy/Approval 目前是 P0 设计/开发前置，不被误报为 P1 运行时授权完成；
- 普通 Docker/Windows 容器不被描述为绝对反逃逸边界；P5 仍需 gVisor/Kubernetes 等隔离执行面；
- 静态 secret 扫描未发现常见凭据模式，真实本机配置和备份均被忽略。

## 8. 测试内容和测试结果

2026-07-15 在 Windows、Python 3.12、Node.js 22.17、pnpm 10.30、Docker Desktop 28.4.0 环境复核：

| 门禁 | 真实结果 |
|---|---|
| Ruff | All checks passed |
| mypy | 29 source files，0 issues |
| pytest | 60 passed in 13.30s；包含 18 项契约/迁移测试 |
| OpenAPI runtime / JSON Schema / migration 静态检查 | 全部 valid；5 operations；2 schemas；1 migration pair |
| pip check / pip-audit strict | 无损坏依赖；无已知漏洞 |
| pnpm lint/typecheck/test/build | 每项 6/6 tasks successful |
| 前端单元测试 | API client、Web、UI 各 1 项通过 |
| Playwright Chrome | 1 passed in 7.4s |
| bundle budget | 16 assets，gzip 合计 532,994 bytes |
| 生成 API 类型 | SHA-256 `6BA201F9EC96B3EE91D754A3809A09DD421D25AA3320FD1CB6F82C076ED74BEA` |
| Compose | base、identity、tools 三种模型解析通过 |
| Docker 平台 | 9 个基础服务 + Keycloak healthy；HTTP/OIDC/MinIO/Prometheus smoke 通过 |
| PostgreSQL | up/down/up、18 个复合租户 FK、追加审计与跨租户负向测试通过 |
| 备份恢复 | 5 类数据产物 + manifest + checksum；6 行 hash；恢复核对通过 |
| Helm 3.17.3 | strict lint 通过；渲染 14 个资源 |
| PowerShell/POSIX 脚本 | 7 个 ps1 与全部 sh 语法通过 |
| 静态 secret 扫描 | 202 个待提交源文件，0 findings |

完整命令和环境限制记录在验收报告中；远端 GitHub Actions 因没有配置远端仓库而未运行，未被声称为通过。

## 9. 本地运行命令

```powershell
cd 'D:\多模协同漏洞利用智能挖掘系统'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --editable .
pnpm install --frozen-lockfile
pnpm generate:api
.\.venv\Scripts\python.exe solve_p0_baseline.py --full

# 平台；先从 example 复制并替换所有 GENERATE_* 值
$env:PLATFORM_GATEWAY_PORT='18080' # 仅当默认 8080 被占用
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure\scripts\start.ps1 -Identity
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure\scripts\backup.ps1
```

## 10. 验证步骤

1. 确认 Git 位于 `main`，工作区没有未预期文件；
2. 运行 `solve_p0_baseline.py --full`，确认顶层 `valid=true` 且 `failed=0`；
3. 运行独立 Python、pnpm、契约、migration、Compose 与 Helm 门禁；
4. 用强随机本地配置启动平台，确认所有 long-running service healthy；
5. 验证网关/Web/health/ready、401、安全头、OIDC discovery/JWKS/PKCE、MinIO 和 Prometheus；
6. 在可丢弃数据库中执行 migration up/down/up 与跨租户/审计负向查询；
7. 执行备份和恢复，并核对 checksum、表数量及网关健康；
8. 确认 `git status --short` 为空，记录基线提交 SHA。

## 11. 当前剩余问题

- P1 尚未实现 OIDC token 消费、Tenant/Organization/Project、八角色后端授权、RLS/repository scope 和统一追加审计；
- 兼容运行时仍使用 API Key、SQLite、单进程状态和四角色，只用于迁移回归；
- P2–P8 的模型网关、持久 Agent 编排、RAG、授权资产、Policy/Sandbox、受控验证和完整企业页面均未实现；
- Helm 只完成 P0 lint/render，不包含生产集群部署、签名镜像、provenance、告警和灾备演练；
- 没有 GitHub 远端，远端 Actions、分支保护、PR 审批和制品留存需要在接入仓库后验证；
- P0 通过不等于企业 MVP 或生产安全认证通过。

## 12. 下一阶段建议

严格进入 P1：先实现 OIDC/JWT 与服务身份，再落地租户/项目上下文、八角色 RBAC/ABAC、PostgreSQL repository/RLS、配置 Schema、统一错误/日志和追加审计。为每一权限建立跨租户、对象越权、职责分离、token 撤销和审计篡改负向测试。P1 出口通过后再进入 P2 模型网关与 P3 持久编排；不得绕过身份、策略、审批、审计和 Sandbox 直接开发漏洞验证。
