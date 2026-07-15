# 测试与质量策略

## 1. 目标与原则

测试证明具体边界内的行为，不用于把原型能力升级为企业完成态。每项声明必须关联可重复命令、环境、版本、结果和失败/跳过原因。

核心原则：

1. 安全不变量优先于 happy path；跨租户、越权、Scope 越界、secret 泄漏和执行旁路必须有负向测试。
2. 契约先于实现；OpenAPI、事件和领域协议由生成工具及语义快照保护。
3. 不把 Mock 通过当成真实供应商、真实消息系统或真实隔离环境通过。
4. 测试默认无外网、无真实目标、无真实客户数据、无真实生产凭据。
5. 重复、乱序、超时、取消、重启和部分故障是分布式系统的正常测试场景。
6. Windows 只验证代码、契约和一般容器编排；seccomp/MAC/gVisor 必须在 Linux 测试环境验证。

## 2. 测试层次

| 层次 | 目标 | P0 位置/工具 | 失败影响 |
|---|---|---|---|
| 静态与类型 | 语法、类型、依赖边界、前端规则 | `compileall`、ESLint、TypeScript | 阻断合并 |
| 单元 | 纯规则、序列化、状态映射、脱敏、Scope | Pytest、Vitest | 阻断合并 |
| 契约 | OpenAPI/JSON Schema、生成 SDK、迁移结构 | `tests/contract`、`tools/contracts` | 阻断合并 |
| 组件 | API + SQLite 兼容存储、前端组件 | FastAPI TestClient、Testing Library | 阻断合并 |
| 集成 | PostgreSQL/Redis/NATS/MinIO/OTel 真连接 | Compose 测试环境 | 阻断阶段出口 |
| 端到端 | 浏览器到 Gateway/API/事件的用户旅程 | Playwright + 合成数据 | 阻断发布 |
| 安全 | RBAC/ABAC、租户隔离、SSRF、secret、Sandbox | 负向测试、SAST/DAST、Linux 隔离集群 | 安全失败关闭 |
| 性能/可靠性 | SLO、背压、恢复、故障和容量 | k6/Locust、故障注入、长稳 | 阻断生产验收 |

P0 现有 `tests/test_*.py` 是旧原型 characterization 与安全回归；`tests/contract/` 是目标 P0 契约/迁移基线。两者必须分别报告，不能把旧 SQLite 测试计作 PostgreSQL 多租户验证。

## 3. 测试数据与环境

环境分级：

- `unit`：无网络、临时目录、固定时钟/随机种子、纯 Mock。
- `component`：临时 SQLite，仅验证兼容行为；进程结束即销毁。
- `integration`：临时 Compose project 和独立 named volumes，使用随机非默认 secret。
- `security-lab`：专用 Linux 网络和合成 vulnerable/patched target，无互联网路由。
- `staging`：与生产拓扑相似的匿名合成数据；不克隆客户 secret。

测试资源使用唯一 `tenant_id/project_id/task_id`，并在测试后按 manifest 回收。高风险测试必须显式声明允许的 CIDR、端口、工具 digest、时间窗和责任人。任何请求解析到允许范围外立即失败。

## 4. P0 可执行质量门

### Python 与兼容回归

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m compileall -q apps/control-plane/src solve_module2.py
python -m pytest -q -p no:cacheprovider
```

### OpenAPI、事件、协议和迁移

```powershell
python tools/contracts/openapi_snapshot.py check --runtime
python tools/contracts/json_schema_check.py
python tools/contracts/check_migrations.py
python -m pytest tests/contract -q -p no:cacheprovider
pnpm generate:api
```

Git 初始化后追加：

```powershell
git diff --exit-code -- packages/shared-types/src/api.generated.ts
```

### Workspace 与前端

```powershell
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Web 构建同时执行 bundle budget。P0 当前预算脚本限制单个 gzip JavaScript chunk 不超过 1.5 MiB、全部构建资产 gzip 总量不超过 4 MiB；预算变化必须有测量和 ADR/评审依据。

### Compose

```powershell
docker compose --env-file infrastructure/docker-compose/.env.platform.example -f infrastructure/docker-compose/platform.yml config --quiet
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure/scripts/start.ps1
docker compose --env-file infrastructure/docker-compose/.env.platform -f infrastructure/docker-compose/platform.yml ps
```

静态 `config` 通过不能替代镜像构建和 `up --wait`。Docker Engine 不可用时运行态检查标为 `Blocked`。

## 5. 安全测试目录

每个阶段都必须包含以下负向类别：

- 身份缺失、过期、撤销、issuer/audience 错误；
- 同租户跨项目与跨租户读写；
- 创建者自审、审批者执行、撤销/过期 grant；
- 未知字段、超长输入、压缩炸弹、路径穿越和危险 URL；
- 日志、响应、事件、对象 metadata 和异常中的 secret canary；
- 重复 Idempotency-Key、不同 hash 复用、乱序 event 和旧 fencing token；
- 审计不可写、策略不可用、对象存储失败时的 fail-closed；
- Sandbox 特权、HostNetwork、Docker Socket、敏感挂载、外网和资源超限拒绝。

安全测试不得生成武器化载荷、持久化、凭据窃取、破坏、DoS 或规避审计能力。P6 的验证只对合成靶场和明确授权环境运行。

## 6. P1–P8 测试演进

| 阶段 | 新增测试重点 | 阶段出口证据 |
|---|---|---|
| P1 | OIDC/JWT、八角色、RLS、租户/项目负向、Policy/Approval、审计链 | 跨租户矩阵和 SoD 全通过；secret canary 无泄漏 |
| P2 | Provider 契约、流式/工具输出、限流、熔断、主备、Token/成本 | Mock + 一个受控兼容 Provider；凭据 write-only |
| P3 | Task/Stage/Execution 状态机、租约/fencing、重复/乱序、重启恢复、SSE | 多副本故障注入和持久恢复通过 |
| P4 | RAG ACL 前置、引用、污染、删除/重建、Context checkpoint | 跨租户检索全拒绝，引用可复核 |
| P5 | Scope/DNS/代理、ExecutionGrant、Linux Sandbox、配额与回收 | 无授权/外网/宿主访问全拒绝，异常资源最终回收 |
| P6 | vulnerable/patched 对照、Evidence hash、Review、报告引用 | 合成靶场闭环，不把端口/marker 单独当漏洞成立 |
| P7 | 路由、错误/空态、虚拟列表、SSE 重连、a11y、i18n、主题、bundle | Vitest/Playwright/a11y/预算通过 |
| P8 | SLO、容量、长稳、故障、滚动升级、备份恢复、供应链、Kubernetes | 企业 MVP 验收全项有实测证据 |

## 7. 覆盖率与测试质量

覆盖率是发现盲区的指标，不是唯一门禁。P1 起对安全核心（policy、scope、idempotency、state transition、redaction）要求分支覆盖率不低于 90%，普通领域代码不低于 80%；生成代码、声明式 schema 和不可达平台胶水可以按评审排除。

还必须检查：断言是否验证业务结果而非只看 200；失败分支是否覆盖；测试是否会在实现被破坏时真实失败；是否依赖执行顺序、墙钟或外网；fixture 是否隔离 tenant/project；重试是否掩盖竞态。

## 8. 性能与可靠性口径

P8 前为每个 API/任务类型定义负载模型、数据规模、并发、持续时间和硬件。最低报告包含 p50/p95/p99、吞吐、错误率、队列等待、资源使用、成本和背压行为。性能结论必须附原始结果和环境 manifest。

可靠性场景至少覆盖：API/worker 重启、NATS 重复/延迟、PostgreSQL failover、Redis 丢失、对象存储超时、模型 429/5xx、审批撤销、worker 丢失、磁盘压力和 OTel 后端不可用。系统不能因可观测后端故障泄漏数据或绕过安全门禁。

## 9. Flaky、跳过和证据

- Flaky 测试不得直接无限重试；先隔离并创建带责任人和期限的问题记录。
- 跳过必须写明环境条件和影响；安全门禁不能以本地环境不足长期跳过。
- CI 保存 JUnit、覆盖率、Playwright trace、性能摘要、安全扫描、镜像 digest、SBOM 和 Compose/Kubernetes manifest。
- 每份阶段验收报告记录 commit SHA、依赖 lock hash、执行时间、环境、命令、退出码和制品 URI。

## 10. 完成定义

变更只有在相关静态、单元、契约、负向和集成测试通过，生成物无漂移，安全与兼容影响已评审，且没有未解释的跳过时才可合并。阶段只有满足对应验收文档且阻断项为零时才可进入下一阶段。
