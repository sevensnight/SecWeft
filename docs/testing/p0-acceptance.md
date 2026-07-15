# P0 架构与工程基线验收

## 1. 验收结论

记录日期：2026-07-15（Asia/Shanghai）。

**结论：P0 Accepted（本地工程基线）。**

本结论表示阶段 P0 的 17 项架构、契约、工程、基础设施和本地验证产物已经形成可构建、可测试、可回滚的闭环。它不表示 P1–P8 已实现，不表示系统已经达到生产部署条件，也不授权或启用任何真实资产探测、载荷执行或漏洞验证能力。

完整范围、命令、证据和限制以 [`../P0_ACCEPTANCE_REPORT.md`](../P0_ACCEPTANCE_REPORT.md) 为准。

## 2. 强制出口检查

| 出口项 | 结果 | 本地证据 |
|---|---|---|
| P0 需求与能力映射 | Passed | 17 项产物均有责任边界、阶段和验收证据 |
| 架构、数据流、ER、状态机、RBAC、策略审批、风险 | Passed | `docs/architecture`、`docs/security`、ADR |
| API First 与生成类型 | Passed | OpenAPI 5 个只读操作；运行时投影、Schema 和生成 hash 稳定 |
| Python 质量门 | Passed | Ruff、mypy 29 files、pytest 60 passed |
| 前端质量与性能门 | Passed | 6/6 lint/typecheck/test/build；Playwright 1 passed；bundle 预算通过 |
| PostgreSQL migration | Passed | 静态可逆检查与真实 `up → down → up`；15 张表、18 个租户复合外键、追加审计约束 |
| Compose 平台 | Passed | 9 个基础服务 healthy；可选 Keycloak healthy；网关和观测 smoke 通过 |
| 备份恢复 | Passed | 5 类数据产物、manifest、6 行校验清单；恢复后 15 张表且网关 200 |
| Helm 预留 | Passed | strict lint；模板渲染 14 个资源 |
| 依赖与 secret 基线 | Passed | pip-audit strict；2026-07-12 pnpm audit 无已知漏洞；CI Trivy 锁文件门禁；202 个源文件静态 secret 扫描 0 发现 |
| Git 可追溯基线 | Passed | `main` 初始化、忽略规则和提交前文件清单审查；最终提交后由验收器复核 |
| 安全默认值 | Passed | `VULNLAB_LEGACY_EXECUTION_ENABLED=false`；延期执行端点 fail closed |

## 3. 运行环境说明

- Windows、Python 3.12、Node.js 22.17、pnpm 10.30、Docker Desktop 28.4.0、Compose 2.39.2、Helm 3.17.3。
- 本机已有其他项目占用 `127.0.0.1:8080`，本次用 `PLATFORM_GATEWAY_PORT=18080` 验证，未停止或修改无关容器。
- Docker BuildKit 对中文宿主路径存在兼容问题，因此验证使用指向同一项目的 ASCII 目录联接；项目真实位置与产物内容未改变。
- GitHub 远端未配置，所以 GitHub Actions、分支保护、签名发布和远端制品留存没有被声称为已执行；本地运行了对应的质量、部署和安全门。

## 4. P0 边界与下一阶段门禁

- 可选 Keycloak 只证明 P1 OIDC 集成前置条件：issuer、JWKS、Authorization Code/PKCE 元数据可用。兼容 API 仍使用 API Key，尚未消费 OIDC token。
- PostgreSQL、Redis、NATS、MinIO 和 OTel 平台已经可运行，但兼容控制面仍以 SQLite/单进程行为作为迁移参考；P1/P3 才切换企业数据面与持久编排。
- P1 必须先完成 Tenant/Organization/Project、OIDC/JWT、八角色后端授权、PostgreSQL repository/RLS、追加审计和跨租户负向测试。
- 未完成 P1/P5 的身份、策略、授权摘要、审批、审计与 Sandbox 门禁前，不得进入 P6 受控验证执行。
