# P1 企业身份与租户安全基线验收报告

记录日期：2026-07-17（Asia/Shanghai）。

## 1. 结论

Accepted。

P1 已完成企业身份、租户隔离、固定 RBAC、受管配置、追加式审计、OIDC 前端入口和工程验收门禁。当前提交不启用模型调用、Agent 执行、资产探测、Sandbox 或漏洞验证能力。

## 2. 实现证据

| 范围 | 主要证据 |
|---|---|
| OIDC/JWT | `enterprise/auth.py`、OIDC 单元测试、真实 Code+PKCE/JWKS 验证器 |
| Tenant/Project/RLS | `enterprise/repository.py`、`0002` migration、真实双租户负向测试 |
| 八角色 RBAC | `enterprise/permissions.py`、`0003` 范围触发器、allow/deny 参数测试 |
| 最小权限 | `0004` migration、应用角色 DELETE 负向测试、审计表写权限负向测试 |
| 配置 | 受管 Schema、三级覆盖、乐观锁、幂等 |
| 审计/日志 | 每租户 SHA-256 链、append-only trigger、字段白名单 JSON 日志 |
| API/前端 | P1 OpenAPI、生成类型、Bearer API Client、OIDC AuthBoundary、权限裁剪页 |
| 部署 | checksum migration runner、OIDC Compose 配置、无默认业务用户的 Keycloak Realm |

## 3. 最终命令与结果

本次恢复后的本地复跑结果：

| 门禁 | 结果 |
|---|---|
| `ruff format --check .` | PASS，66 files already formatted |
| `ruff check .` | PASS |
| `mypy apps/control-plane/src` | PASS，39 source files |
| `pytest -o addopts=''` | PASS，84 passed，1 skipped |
| `pnpm lint` | PASS，6 packages |
| `pnpm typecheck` | PASS，6 packages |
| `pnpm test` | PASS，6 packages；Vitest 共 5 tests |
| `pnpm build` | PASS，17 assets，541260 gzip bytes |
| `openapi_snapshot.py check` | PASS，19 operations |
| `check_migrations.py` | PASS，0001-0004 四组 up/down migration |
| `solve_p1_baseline.py` | PASS，7/7 |
| `solve_p1_baseline.py --full` | PASS，15/15 |
| `pip-audit -r requirements.lock --no-deps --disable-pip` | PASS，No known vulnerabilities found |
| `pnpm audit --audit-level high --registry=https://registry.npmjs.org` | PASS，No known vulnerabilities found |
| GitHub Actions YAML parse | PASS，1 workflow |
| PowerShell/shell script syntax | PASS |
| `git diff --check` | PASS；仅报告 CRLF 工作区提示 |

此前同一 P1 实施过程中已完成的真实服务验收：

| 门禁 | 结果 |
|---|---|
| 真实 PostgreSQL + RLS + 最小权限验证 | PASS，15 checks |
| 真实 PostgreSQL API 集成测试 | PASS |
| 真实 Keycloak Authorization Code + PKCE/JWKS 验证 | PASS，14 checks |
| 真实浏览器网关 OIDC 入口验证 | PASS，8 checks |
| 完整 Compose 栈健康检查 | PASS，10 services healthy |
| Helm 3.17.3 chart lint/template | PASS，14 rendered resources |

本次恢复后的 Docker Desktop 引擎不可连接：`//./pipe/dockerDesktopLinuxEngine` 不存在，因此未在 2026-07-17 这次复跑中重新执行镜像构建、容器栈、Trivy 容器扫描、PostgreSQL/Keycloak/浏览器 live checks。相关能力已经保留在 `solve_p1_baseline.py --postgres/--keycloak/--browser` 和 `tools/p1/*` 中，Docker 恢复后可直接复验。

## 4. 明确限制

- 开发 Keycloak 不是生产身份平台；生产必须接入组织托管 IdP、HTTPS、MFA 和集中 secret manager。
- P1 的 Organization/Project 是安全管理基线，不包含 P7 的完整管理交互。
- P2–P8 尚未因 P1 完成而自动获得完成状态。
- 未配置 GitHub 远端时，不声称 GitHub Actions、分支保护或远端制品证明已执行。
- 本阶段未运行任何漏洞验证、资产扫描或外部目标访问。
