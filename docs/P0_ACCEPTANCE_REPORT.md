# 模块二 P0 架构与工程基线验收报告

验收日期：2026-07-15（Asia/Shanghai）
项目：多模协同漏洞利用智能挖掘系统
阶段：P0 架构与工程基线
结论：**P0 Accepted（本地工程基线）**
实施基线提交：`P0_IMPLEMENTATION_SHA`（创建基线提交后回填）

本结论只覆盖 P0。P1–P8、企业 MVP、生产部署和具体漏洞验证能力均不在本次完成声明内。

## 1. 本次完成目标

在保留可用旧原型行为的前提下，完成企业级演进所需的架构、契约、数据、前端、基础设施、质量和安全底座，并用真实构建、容器、数据库、备份恢复与浏览器测试闭环。总提示词指定的 17 项 P0 产物对应如下：

| # | P0 产物 | 落地产物 | 状态 |
|---:|---|---|---|
| 1 | 需求拆解与能力矩阵 | `docs/architecture/01-requirements-capability-matrix.md` | Accepted |
| 2 | 系统总体架构 | `02-system-context-and-service-boundaries.md`、架构入口 | Accepted |
| 3 | 跨服务数据流 | `03-data-flows.md` | Accepted |
| 4 | 服务与模块边界 | `02-system-context-and-service-boundaries.md`、ADR-0001/0002 | Accepted |
| 5 | Monorepo 完整目录 | `apps`、`packages`、`infrastructure`、`tests`、`tools` | Accepted |
| 6 | 技术选型与理由 | 架构文档、ADR、开发/部署文档 | Accepted |
| 7 | 核心领域实体 | `04-domain-model-and-er.md` | Accepted |
| 8 | 数据库初步 ER | ER 文档 + `0001_p0_enterprise_baseline` migration | Accepted |
| 9 | 任务状态机 | `05-task-state-machine.md` | Accepted |
| 10 | 权限矩阵 | `docs/security/rbac-permission-matrix.md` | Accepted（设计；P1 执行面待实现） |
| 11 | 策略与人工审批 | `policy-and-approval-flow.md`、ADR-0003/0004 | Accepted（设计；P1/P5 执行面待实现） |
| 12 | API 分组/OpenAPI 原则 | `packages/api-contracts`、`docs/api` | Accepted |
| 13 | 阶段与里程碑 | `06-milestones.md` | Accepted |
| 14 | 技术风险与规避 | `07-risk-register.md` | Accepted |
| 15 | 最小企业版本验收标准 | `docs/testing/enterprise-mvp-acceptance.md`、本报告 | Accepted |
| 16 | 目录、配置、文档、Compose | 根配置、Compose、Keycloak、监控、脚本、Helm | Accepted |
| 17 | 基础构建和测试 | 本报告第 8 节、`solve_p0_baseline.py` | Accepted |

## 2. 架构和实现说明

系统采用 API First Monorepo 和演进式服务拆分：

- 入口层：Caddy API Gateway 统一路由与安全头；Web Console 与 Control Plane 分离部署。
- 契约层：OpenAPI 3.1、任务事件 Schema、Tool/Skill/Agent/Workflow/Policy/Result/Evidence 协议是跨语言边界；TypeScript DTO 自动生成。
- 控制面：FastAPI 旧兼容实现已拆为 routers/services/dependencies/serializers/runtime/config，防止继续形成单文件 Controller/Service。
- 企业数据底座：PostgreSQL 负责 IAM/Control/Audit 事务模型，NATS JetStream 负责事件预留，Redis 负责缓存/限流预留，MinIO 负责产物，OTel/Prometheus 负责可观测性。
- 身份前置：可选 Keycloak profile 提供固定 realm、issuer、JWKS 与 PKCE 元数据；P1 才由 API 消费 JWT 并注入租户上下文。
- 前端：React/TypeScript/Vite + TanStack Query/Router + Zustand + Ant Design；路由、图表和编辑器延迟加载，任务列表虚拟滚动，SSE 增量流，Web Worker 过滤，表单由 React Hook Form/Zod 校验。
- 交付：Compose 支持基础、identity 和 tools profiles；Helm 提供受限容器、Service、NetworkPolicy、PDB、PVC 等 P8 前置模板。

所有高风险能力都保持阶段门：P0 不把模型/Agent 输出当权限，不允许通过兼容开关绕过未来 Policy、Approval、Audit、Scope 和 Sandbox。

## 3. 新增或修改的文件

本次仓库基线包含约 200 个受审查源文件，主要分组：

- 根工程：`pyproject.toml`、Python hash lock、pnpm lock/workspace、Turbo、Makefile、Taskfile、环境示例和忽略规则；
- 应用：`apps/api-gateway`、`apps/control-plane`、`apps/web-console`；
- 共享包：`api-contracts`、`api-client`、`shared-types`、`config`、`ui-components`；
- 基础设施：Compose、数据库初始化/migration、NATS、Keycloak、OTel/Prometheus、备份恢复、Helm；
- 自动化：GitHub Actions、CODEOWNERS、Dependabot、PR 模板；
- 测试/工具：Python 单元与契约测试、Vitest、Playwright、契约快照和 P0 验收脚本；
- 文档：架构、安全、API、部署、测试、工程规范、ADR、题解和本报告。

构建物、`.venv`、`node_modules`、本地数据库、`.env.platform`、备份、浏览器报告和下载工具均被排除在 Git 外。

## 4. 数据库变更

新增可逆 migration：

- `infrastructure/migrations/0001_p0_enterprise_baseline.up.sql`
- `infrastructure/migrations/0001_p0_enterprise_baseline.down.sql`

真实 PostgreSQL 17.4 运行证据：

- 完成 `up → down → up`；
- `iam`、`control`、`audit` 共 15 张表；
- 18 个携带 `tenant_id` 的复合外键；
- 1 个追加审计保护触发器；
- 跨租户 task 外键插入被数据库拒绝；
- audit event UPDATE 被数据库拒绝；
- 备份包含 PostgreSQL dump、API/Redis/NATS/MinIO 五类数据产物、manifest 与 checksum；6 条 hash 校验通过；
- 恢复成功，恢复后再次核对 15 张表与网关 200。

P0 migration 是企业数据模型基线，兼容 API 尚未切换到该 repository，不得据此声称 P1 多租户运行时已经完成。

## 5. API 变更

权威契约：`packages/api-contracts/openapi/v1.yaml`。P0 锁定 5 个只读操作：

1. `GET /api/v1/system/requirements`
2. `GET /api/v1/tasks`
3. `GET /api/v1/tasks/{task_id}`
4. `GET /api/v1/tasks/{task_id}/events`
5. `GET /api/v1/tasks/{task_id}/events/stream`

OpenAPI 语义快照锁定 operationId、路径、参数、状态码和成功媒体类型；运行时投影检查防止规范与 FastAPI 漂移。SSE 支持 `Last-Event-ID`，从持久任务事件序列恢复，返回 keepalive。生成 TypeScript 类型的 SHA-256 为：

`6BA201F9EC96B3EE91D754A3809A09DD421D25AA3320FD1CB6F82C076ED74BEA`

没有新增 P6 验证写 API。旧写/执行路径只作为兼容接口存在，并在安全默认值下返回 503。

## 6. 配置变更

- Python 3.12、Node 22.17、pnpm 10.30.1 和 Helm 3.17.3 均有版本基线；
- Python 生产/开发依赖均由带 hash lock 安装，pnpm 使用 frozen lockfile；
- `.env.example` 和 Python Settings 将执行模式设为 `dry_run`、遗留执行设为 `false`；
- `.env.platform.example` 只包含生成占位符，启动脚本校验所有 secret；
- 内部数据服务只连接 `backend` 内网；Keycloak、MinIO Console、Prometheus 通过独立 management 网络绑定 `127.0.0.1`；
- 本次因本机 8080 被无关容器占用，使用 `PLATFORM_GATEWAY_PORT=18080`，未修改或停止用户的其他项目；
- CI 用 pip-audit 和 Trivy lockfile/filesystem gate。npm registry 在 2026-07-15 对 pnpm 旧 audit 端点返回 410，已移除这一脆弱依赖，保留 Trivy 的 HIGH/CRITICAL 强制门及 CycloneDX SBOM。

## 7. 安全影响

正向控制：

- 遗留执行、探测、沙箱入口默认关闭且 fail closed；
- API Key 不在 URL/本地持久化/日志传播；网关存在 CSP 等响应头；
- 容器非 root、只读根文件系统、禁特权、capability 收缩、健康检查和资源限制；
- 数据面默认不映射宿主端口；管理端口仅回环；
- migration 用多租户复合外键、幂等键、Outbox/Inbox 和追加审计；
- secret 模式扫描覆盖 202 个待提交文件且 0 发现；忽略规则验证本地 secret、备份和数据库不会提交；
- 依赖升级消除了 pytest 旧版本公告，pip-audit strict 无漏洞；Node 锁文件已通过依赖审计并由 CI Trivy 持续强制。

剩余边界：Keycloak 健康不等于 API 已完成 OIDC；Compose 容器不等于强 Sandbox；P0 控制面仍是兼容 API Key/SQLite。上述能力都在 P1/P5/P8 门禁内，不作安全夸大。

## 8. 测试内容和测试结果

本地最终复核环境：Windows，Python 3.12，Node.js 22.17，pnpm 10.30，Docker Desktop/Engine 28.4.0，Compose 2.39.2，Helm 3.17.3。

| 检查 | 真实结果 |
|---|---|
| `ruff check .` | 通过 |
| `mypy apps/control-plane/src/vulnlab` | 29 source files，0 issues |
| `pytest -q` | 60 passed in 13.30s |
| 契约测试 | 18 项包含于全量测试；OpenAPI 5 operations、2 schemas、1 migration pair 均 valid |
| `pip check` | No broken requirements |
| `pip-audit -r requirements-dev.lock --strict` | 退出码 0，无已知漏洞 |
| `pnpm install --frozen-lockfile` | 通过 |
| `pnpm generate:api` | 通过，生成 hash 稳定 |
| `pnpm lint/typecheck/test/build` | 每项 6/6 tasks successful |
| Vitest | 3 个包各 1 项测试通过 |
| Playwright（本机 Chrome） | 1 passed in 7.4s |
| Bundle 预算 | 16 assets，gzip 532,994 bytes |
| Compose config | base、identity、tools profiles 通过 |
| Docker build checks | API/Gateway/Web/OTel Dockerfile 均 0 warnings |
| Compose runtime | 9 个基础 long-running services + Keycloak healthy；MinIO init exit 0 |
| HTTP/API smoke | Gateway/Web/health/ready/requirements 200；CSP 存在；未认证 tasks 401；legacy execution false |
| OIDC smoke | issuer 正确，PKCE S256=true，JWKS keys=2 |
| Observability/object storage | Prometheus 200，MinIO live 200 |
| PostgreSQL migration/constraints | up/down/up；15 tables；18 tenant FKs；append-only/cross-tenant negatives 通过 |
| 备份恢复 | 5 类数据产物、manifest、6 checksum；恢复及表/网关核对通过 |
| Helm | strict lint 0 failures；render 14 resources |
| PowerShell/POSIX | 7 个 ps1 和全部 sh 语法通过 |
| 静态 secret scan | 202 files，0 findings |

未执行/不能确认：没有 GitHub 远端，因此 Actions 托管运行、分支保护、PR 审批、远端 artifact/SBOM 留存、镜像签名和 provenance 未执行。2026-07-15 的 `pnpm audit` 重跑被 npm registry 已退役端点返回 410；本地 Trivy 0.60.0 镜像首次拉取长时间无进展后只终止了该 `docker.exe` 客户端，因此没有声称本次 Trivy 本地扫描通过。当前 Node 依据是 2026-07-12 已成功的 pnpm audit（无已知漏洞）和未变化的锁文件；CI 已改用能直接读取 pnpm lockfile 的 Trivy 强制门。接入远端后必须让该门真实运行并保存 SBOM。

## 9. 本地运行命令

```powershell
cd 'D:\多模协同漏洞利用智能挖掘系统'

# 可重复安装
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --editable .
pnpm install --frozen-lockfile

# 全量本地门禁
.\.venv\Scripts\python.exe solve_p0_baseline.py --full
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy apps/control-plane/src/vulnlab
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
pnpm lint
pnpm typecheck
pnpm test
pnpm build
$env:PLAYWRIGHT_CHANNEL='chrome'; pnpm --filter @vulnlab/web-console test:e2e

# 平台（先复制 example 并替换全部 GENERATE_*）
$env:PLATFORM_GATEWAY_PORT='18080' # 仅当 8080 被占用
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure\scripts\start.ps1 -Identity
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure\scripts\backup.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure\scripts\stop.ps1

# Helm
helm lint infrastructure/kubernetes/helm/vulnlab-platform --strict
helm template p0 infrastructure/kubernetes/helm/vulnlab-platform --namespace vulnlab --set global.imagePullPolicy=Never
```

## 10. 验证步骤

1. 从干净 clone 安装 hash/frozen lock，禁止跳过 hash；
2. 运行 `solve_p0_baseline.py --full`，要求 `valid=true`、`failed=0`；
3. 单独运行 Python、pnpm、Playwright、契约和 migration 门，确认生成 DTO 无漂移；
4. 用本地强 secret 启动基础/identity 平台，要求所有长期服务 healthy；
5. 检查网关/Web/health/ready/401/CSP 和 execution=false；
6. 检查 OIDC issuer、JWKS、PKCE S256、MinIO、Prometheus；
7. 在可丢弃 PostgreSQL 执行 up/down/up、跨租户和追加审计负向测试；
8. 执行备份、checksum 和恢复，复核表数与网关；
9. strict lint/render Helm，解析所有 PowerShell/POSIX 脚本；
10. 扫描 secret/依赖，确认本机文件被忽略；最后确认 Git 工作区干净并记录 SHA。

## 11. 当前剩余问题

- 兼容 API 仍使用 API Key、SQLite、单进程任务状态和四角色；P1/P3 才迁移企业真相源和持久编排。
- Keycloak 已可运行，但 API/Web 尚未消费 OIDC/JWT，八角色 RBAC/ABAC、租户注入、RLS 和 token 生命周期属于 P1。
- P2 模型/凭据网关、P3 Agent/Skill/Workflow、P4 Context/RAG、P5 Asset/Policy/Sandbox、P6 受控验证、P7 全业务前端、P8 生产化均未实现。
- Helm 仅为可渲染预留，尚未在真实 Kubernetes 集群做升级、回滚、网络策略、故障和容量验证。
- 没有远端 GitHub 仓库，远端 CI、分支保护、代码所有者审批、SBOM artifact、签名镜像和 release provenance 待接入。
- 本地 8080 冲突和中文路径 BuildKit 兼容问题均有可复现绕行方案，但后续应在 CI/Linux 干净路径再次运行。

这些限制不会被转换为“已实现”状态，也不影响“P0 本地工程基线”的限定验收。

## 12. 下一阶段建议

下一步只进入 P1：

1. OIDC Authorization Code + PKCE、JWT/JWKS 校验、服务身份、token 撤销/轮换；
2. Tenant/Organization/Project 与请求级上下文；
3. 八角色 RBAC + 数据/模型/技能/资产/审批/导出权限，后端默认拒绝；
4. PostgreSQL repository、RLS、乐观锁与跨租户负向测试；
5. 统一错误、结构化日志、request/trace 标识和追加审计；
6. 分层配置 Schema 与 secret provider 接口；
7. P1 出口做越权、跨租户、SoD、JWT 生命周期、审计篡改和故障测试。

P1 验收前不得进入 P6；P5/P6 任何高风险执行还必须重新验证授权范围、策略 digest、审批状态、审计可写性与强 Sandbox。
