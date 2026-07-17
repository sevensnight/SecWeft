# P1 身份、租户、权限、配置与审计验收

## 1. 验收边界

P1 只验收企业控制面的安全基础，不开放模型调用、Agent 编排、资产探测、Sandbox 或漏洞验证。验收对象包括：

- OIDC Authorization Code + PKCE 与后端 Bearer JWT 校验；
- 可选的精确 ACR 强制值，用于接入组织 IdP 的 MFA/认证强度策略；
- Tenant、Organization、Project、User 与固定八角色；
- PostgreSQL RLS、显式 TenantContext 和最小权限应用角色；
- 角色授予、撤销、过期和项目/租户范围；
- 租户、项目、用户三级业务配置；
- 统一错误、结构化日志、request/trace 关联；
- 追加式哈希链审计；
- P1 OpenAPI、生成类型、Web Console 权限裁剪。

兼容 API Key/SQLite 运行时仍可在 `VULNLAB_AUTH_MODE=compatibility` 下用于迁移回归，但不是 P1 验收证据。生产环境必须使用 `oidc`，否则配置加载失败。

## 2. 阶段出口

| 门禁 | 通过条件 |
|---|---|
| 身份 | 仅 RS256；必须有 `kid`；精确校验 `iss/aud/exp/iat`；`tenant_id` 必须是 UUID；错误不泄漏 token 或内部异常 |
| 浏览器登录 | Authorization Code + S256 PKCE；禁用 implicit/direct grant；访问令牌只在内存；OIDC state 只暂存在 sessionStorage |
| Token 生命周期 | 开发 Realm 的访问令牌不超过 5 分钟；Refresh Token 单次轮换；登录防暴力破解；登录和管理事件开启 |
| 租户隔离 | 所有多租户表启用并强制 RLS；应用事务必须设置本地 `app.tenant_id`；跨租户查询不可见 |
| 数据库最小权限 | `vulnlab_app` 不能修改/删除审计事件，也不能物理删除 IAM/Control 业务数据 |
| RBAC | 仅八个固定角色；无 `*` 或 `admin` 通配权限；租户角色不可授到项目，项目角色不可授到租户；平台管理员不能执行 Task |
| 撤权 | 新请求立即重新解析有效角色；撤销或过期分配不再产生权限 |
| 项目与成员 | Organization/Project/User 创建和列表受服务端权限、RLS、游标分页、幂等键保护 |
| 配置 | 仅接受受管 Schema；拒绝 secret 类 key；Tenant → Project → User 确定性覆盖；写入使用乐观版本 |
| 审计 | 关键管理写入和授权拒绝生成含 tenant/actor/request/trace 的事件；哈希链与数据库触发器阻止篡改 |
| API | P1 契约、FastAPI 运行时投影和 TypeScript 生成物一致；错误返回稳定 code、HTTP 状态和关联 ID |
| 前端 | 权限和项目范围来自 `/session`；菜单/查询按有效权限裁剪；直接 API 越权仍由后端拒绝 |
| 工程 | Ruff format/check、mypy、pytest、pnpm lint/typecheck/test/build、migration、Compose、真实 PostgreSQL/Keycloak 验证通过 |

## 3. 自动验收

只读静态检查：

```powershell
.\.venv\Scripts\python.exe solve_p1_baseline.py
```

本地完整质量门：

```powershell
.\.venv\Scripts\python.exe solve_p1_baseline.py --full
```

真实 PostgreSQL 检查必须指向可丢弃的独立测试库：

```powershell
$env:P1_POSTGRES_ADMIN_DSN = 'postgresql://postgres:<test-password>@127.0.0.1:<port>/vulnlab'
$env:P1_POSTGRES_APP_DSN = 'postgresql://vulnlab_app:<test-app-password>@127.0.0.1:<port>/vulnlab'
$env:P1_POSTGRES_APP_PASSWORD = '<test-app-password>'
.\.venv\Scripts\python.exe tools\p1\validate_enterprise_postgres.py
```

真实 Keycloak 检查要求已从仓库 Realm 文件创建的临时实例；脚本只创建并删除一个临时测试用户：

```powershell
$env:P1_KEYCLOAK_URL = 'http://127.0.0.1:8081'
$env:P1_KEYCLOAK_REALM = 'vulnlab-development'
$env:P1_KEYCLOAK_ADMIN_USER = '<test-admin>'
$env:P1_KEYCLOAK_ADMIN_PASSWORD = '<test-admin-password>'
node tools\p1\validate_keycloak_oidc.mjs
```

浏览器入口检查要求网关与 OIDC Provider 已启动，且 Provider 已允许该网关的 callback URI：

```powershell
$env:P1_GATEWAY_URL = 'http://127.0.0.1:8080'
$env:P1_OIDC_BROWSER_ORIGIN = 'http://127.0.0.1:8081'
# 若部署配置了 VULNLAB_OIDC_REQUIRED_ACR，同时设置：
# $env:P1_EXPECTED_ACR_VALUES = 'urn:example:loa:mfa'
node tools\p1\validate_oidc_browser_entry.mjs
```

该检查会启动无头 Chromium，验证网关 CSP、OIDC discovery、Authorization Code、S256 PKCE、同源 callback，并确认浏览器 URL 中没有令牌。

## 4. 人工核对

1. 查看 `/api/v1/session`，确认 tenant 权限和每个 project 权限分开返回。
2. 用只读主体直接调用角色授予接口，确认返回 `403 permission_denied`，且审计存在 `authorization.denied`。
3. 用 Tenant A token 替换资源 ID 为 Tenant B 的 UUID，确认 RLS 不返回对象。
4. 重放同一个写请求和幂等键，确认不产生第二个资源；更换请求体后返回 `409 idempotency_key_reused`。
5. 更新配置时使用旧版本，确认返回 `409 version_conflict`。
6. 确认浏览器 localStorage、URL、控制台日志和响应中不存在 access token。

## 5. 明确延期

- P2 才实现模型 Provider、凭据、限流、熔断、成本与调用审计。
- P3 才实现服务身份、持久 Task/Agent 编排、消息消费与运行中安全边界重评。
- P5 才实现完整 Policy Engine、多级 Approval、授权资产与 Sandbox。
- P6 前不得启用任何漏洞验证能力。
- P8 才形成生产级 HA、外部审计锚定、Kubernetes 运行证明和容量/SLO 结论。
