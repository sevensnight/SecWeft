# 模块二：多模协同漏洞利用智能挖掘系统

本仓库已完成“阶段 P0：架构与工程基线”和“阶段 P1：用户、租户、权限和审计”。当前交付建立了可构建、可测试、可审计的企业安全底座；不宣称 P2–P8 已实现，也没有新增或默认启用真实漏洞验证能力。

## 当前结论

| 范围 | 状态 | 说明 |
|---|---|---|
| P0 架构与工程基线 | **Accepted（本地工程基线）** | 需求矩阵、服务边界、数据流、ER、状态机、RBAC、策略审批、风险、ADR、Monorepo、契约、迁移、Compose、Helm、CI 与本地运行证据均已闭环 |
| Legacy 单节点参考运行时 | 保留且默认安全关闭 | SQLite、API Key、四角色和进程内任务只用于行为回归，不是企业目标架构 |
| P1 身份/租户/RBAC/配置/审计 | **Accepted（本地与容器集成基线）** | OIDC/JWT、Tenant/Organization/Project、PostgreSQL RLS、固定八角色、三级配置、幂等、统一错误/日志和追加审计已接入企业运行时 |
| P2–P8 | Planned | 严格按里程碑推进，P5/P6 前不得启用受控验证链 |

安全默认值：

- `VULNLAB_LEGACY_EXECUTION_ENABLED=false`；旧任务执行、资产探测和沙箱端点返回 `503`。
- 禁止公网无授权扫描、武器化利用、持久化、凭据访问、规避审计和宿主机任意执行。
- 模型、Agent、RAG、上下文和工具描述不能授予权限；未来执行必须再次经过 PDP/PEP、审批、授权摘要和 Sandbox。
- 开发 Keycloak 只在可选 `identity` profile 中启动，不包含默认用户或业务凭据。

## 快速验收（Windows）

环境：Python 3.12、Node.js 22.17、pnpm 10.30、Docker Desktop（运行平台时需要）。

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --editable .
pnpm install --frozen-lockfile
pnpm generate:api
.\.venv\Scripts\python.exe solve_p1_baseline.py --full
```

独立质量门：

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy apps/control-plane/src/vulnlab
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
pnpm lint
pnpm typecheck
pnpm test
pnpm build
$env:PLAYWRIGHT_CHANNEL='chrome'; pnpm --filter @vulnlab/web-console test:e2e
```

`solve_p1_baseline.py` 默认只读：校验 P1 文件、安全配置、固定角色、Keycloak Realm、OpenAPI/运行时投影、migration 和 Compose；`--full` 执行 Python 与 pnpm 门禁。它不会启动容器、探测目标或执行验证任务。

## 本地开发

启动兼容 API（保持执行能力关闭）：

```powershell
$env:VULNLAB_ADMIN_KEY = '替换为至少 24 字符随机值'
$env:VULNLAB_MASTER_KEY = '替换为 Fernet Key'
$env:VULNLAB_LEGACY_EXECUTION_ENABLED = 'false'
.\.venv\Scripts\python.exe solve_module2.py serve --host 127.0.0.1 --port 8000
```

启动 Web Console：

```powershell
pnpm --filter @vulnlab/web-console dev
```

控制台 P0 页面包括综合态势、虚拟化任务列表、任务详情/SSE 增量事件和系统能力视图。路由、ECharts 和 Monaco 均按需加载；API Key 只保存在页面内存，不进入 URL、localStorage 或日志。

## Docker Compose 平台

复制环境模板并替换每一个 `GENERATE_*` 值；启动脚本会拒绝占位符、短口令和非法 Fernet Key。

```powershell
Copy-Item infrastructure\docker-compose\.env.platform.example infrastructure\docker-compose\.env.platform
# 编辑忽略提交的 .env.platform
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure\scripts\start.ps1
```

可选开发 OIDC：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure\scripts\start.ps1 -Identity
```

基础平台包含 API Gateway、Web Console、Control Plane、PostgreSQL、Redis、NATS JetStream、MinIO、OpenTelemetry Collector 和 Prometheus。`VULNLAB_AUTH_MODE=oidc` 时，P1 企业 API 使用 PostgreSQL、RLS 和 Bearer JWT；`compatibility` 仅保留 SQLite/API Key 迁移回归。持久 Task/Agent 编排仍属于 P3。

## API First

- 唯一审查契约：`packages/api-contracts/openapi/v1.yaml`。
- 事件信封：`packages/api-contracts/events/task-event.v1.schema.json`。
- Tool/Skill/Agent/Workflow/Policy/Result/Evidence 协议：`packages/api-contracts/protocol/domain-protocol.v1.schema.json`。
- TypeScript DTO 由 `openapi-typescript` 生成到 `packages/shared-types/src/api.generated.ts`，禁止手写重复 DTO。
- P1 契约包含 19 个运行时 operation：保留 P0 只读投影，并新增会话、租户、组织、项目、成员、角色、配置和审计 API。

## Monorepo

```text
apps/
  api-gateway/       Caddy 入口、路由和安全头
  control-plane/     模块化 FastAPI 兼容运行时
  web-console/       React/TypeScript/Vite 企业控制台基线
packages/
  api-contracts/     OpenAPI、事件和领域协议
  api-client/        生成类型驱动的请求客户端
  shared-types/      自动生成 DTO
  ui-components/     公共组件
  config/            TypeScript/ESLint 共享配置
infrastructure/
  docker-compose/    平台与可选 identity profile
  migrations/        可逆 PostgreSQL P0/P1 migration 与最小权限收紧
  monitoring/        OTel/Prometheus
  kubernetes/helm/   可渲染部署预留
  scripts/           启停、测试、备份和恢复
docs/                架构、API、安全、部署、测试、ADR、工程规范
tests/contract/      契约与迁移负向测试
tools/contracts/     快照和静态校验工具
```

## 关键文档

- 架构入口：[`docs/architecture/README.md`](docs/architecture/README.md)
- 需求能力矩阵：[`docs/architecture/01-requirements-capability-matrix.md`](docs/architecture/01-requirements-capability-matrix.md)
- 服务边界：[`docs/architecture/02-system-context-and-service-boundaries.md`](docs/architecture/02-system-context-and-service-boundaries.md)
- 领域模型与 ER：[`docs/architecture/04-domain-model-and-er.md`](docs/architecture/04-domain-model-and-er.md)
- 任务状态机：[`docs/architecture/05-task-state-machine.md`](docs/architecture/05-task-state-machine.md)
- RBAC：[`docs/security/rbac-permission-matrix.md`](docs/security/rbac-permission-matrix.md)
- 策略审批：[`docs/security/policy-and-approval-flow.md`](docs/security/policy-and-approval-flow.md)
- P0 验收：[`docs/testing/p0-acceptance.md`](docs/testing/p0-acceptance.md)
- P0 完整验收报告：[`docs/P0_ACCEPTANCE_REPORT.md`](docs/P0_ACCEPTANCE_REPORT.md)
- P1 验收标准：[`docs/testing/p1-acceptance.md`](docs/testing/p1-acceptance.md)
- P1 完整验收报告：[`docs/P1_ACCEPTANCE_REPORT.md`](docs/P1_ACCEPTANCE_REPORT.md)
- P1 实现题解：[`solution_module2_p1.md`](solution_module2_p1.md)
- 本次重构题解：[`solution_module2_p0_refactor.md`](solution_module2_p0_refactor.md)
- 旧原型证据（非企业验收）：[`docs/ACCEPTANCE_MATRIX.md`](docs/ACCEPTANCE_MATRIX.md)

## 下一阶段

进入 P2：在 P1 身份、数据范围和审计边界上实现模型供应商、模型实例、write-only 凭据、流式/结构化调用、限流、熔断、成本与调用审计。P3 再实现服务身份和持久 Task/Agent 编排；不得跳过 P5 授权、策略、审批和 Sandbox 直接开发漏洞验证。
# P14 enterprise acceptance status

Current target version: `2.14.0-p14`.

P14 adds final enterprise acceptance, requirement traceability, candidate delivery package generation, data governance metadata, secret lifecycle posture, compliance evidence mapping, upgrade/rollback deterministic checks, and a unified production readiness gate.

Authoritative GitHub/Linux isolated runtime artifacts are recorded for source commit `59efe16144563f57033724c00ea70cfe895ba890`, so the P14 production readiness gate is accepted:

```json
{
  "runtime": true,
  "runtime_not_claimed": false,
  "production_ready": true,
  "failed": 0,
  "skipped": 0,
  "critical_gates_failed": 0
}
```

Authoritative evidence:

- GitHub Actions run ID: `30195998389`
- Runner: `ubuntu-24.04` / `Linux-6.17.0-1020-azure-x86_64-with-glibc2.39`
- Docker: `28.0.4`
- kind: `v0.27.0`
- Kubernetes: `v1.32.2`
- Helm: `v3.17.3`
- Control Plane replicas: desired `3`, available `3`, ready `3`
- Worker replicas: desired `3`, available `3`, ready `3`
- RPO target: `15` minutes
- RTO target: `60` minutes
- Runtime artifact zip digest: `d0bb0769c16f4721fb9d96d6c0e7a25ad3e2503296a11cfcd55afbcf25cb9273`
- Artifact manifest digest: `b3e93251400c8bbc54ce7472904a1202eada16c2b4a70a5fcddd1c8e55f66465`
- Helm chart digest: `b1b05f65d98e9f1d588ca92b599e9286edf098b6a925d0700e2e684a0c611933`

Useful P14 commands:

```powershell
.\.venv\Scripts\python.exe solve_p14_baseline.py
.\.venv\Scripts\python.exe solve_p14_e2e.py --json
.\.venv\Scripts\python.exe solve_p14_upgrade.py --json
.\.venv\Scripts\python.exe solve_p14_delivery.py --json
```

P14 does not add new vulnerability types, validation templates, scanners, PoC upload, or arbitrary command execution.
