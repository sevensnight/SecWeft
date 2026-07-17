# 模块二 P1 题解：企业身份、租户、RBAC、配置与审计

## 1. 问题分析

P0 已有 API Key/SQLite 兼容运行时和企业架构骨架，但 P1 的关键缺口不是“增加几个接口”，而是建立一条不可被客户端绕过的信任链：

```text
OIDC 签名身份
  → 数据库中的 issuer/sub/tenant 绑定
  → 当前有效角色分配
  → tenant/project 数据范围
  → 明确 permission code
  → 参数化 repository 查询 + PostgreSQL RLS
  → 同事务业务写入与追加审计
```

只在 JWT 中放角色、只隐藏前端按钮、只给 SQL 加 `tenant_id` 条件，都不能单独满足隔离要求。因此实现采用应用层授权与数据库 RLS 双层强制，并让审计、幂等和权限撤销进入同一事务边界。

## 2. 架构方案

### 2.1 身份

- Web Console 使用 OIDC Authorization Code + S256 PKCE。
- access token 仅保存在 Zustand 内存；OIDC 临时 state 使用 sessionStorage；不使用 localStorage。
- 后端只接受 Bearer token，算法固定 RS256，通过显式 JWKS URL 按 `kid` 选键。
- 精确校验 issuer、audience、过期时间、签发时间和 UUID 格式的 tenant claim。
- 可配置一个精确 `acr` 强制值；浏览器通过 `acr_values` 请求同一认证强度，后端独立拒绝缺失或降级的 token，为组织 MFA 策略提供失败关闭扩展点。
- `iss + sub + tenant_id` 必须匹配已预配用户；不存在、停用或租户停用统一认证失败。
- Keycloak 开发 Realm 禁用 implicit/direct grant，使用 5 分钟 access token、Refresh Token 轮换、防暴力破解和身份事件审计。

### 2.2 租户和数据范围

每个 repository 方法都接收 `EnterprisePrincipal`。连接池取得连接后在事务内执行：

```sql
SELECT set_config('app.tenant_id', :tenant_id, true);
```

所有多租户表使用 `FORCE ROW LEVEL SECURITY`，策略只允许 `tenant_id = iam.current_tenant_id()`。即使应用查询遗漏租户条件，数据库仍拒绝跨租户访问。应用角色没有绕过 RLS 权限，也没有业务表物理删除权限。

### 2.3 RBAC

权限代码使用 `resource.action`，八个角色是不可通配的显式权限集合。请求先由数据库解析当前未撤销、已开始、未过期的角色，再把租户权限和各项目权限分别装入不可变集合。

授权查询是集合成员判断：

```text
allowed = permission in tenant_permissions
       or permission in project_permissions[project_id]
```

`platform_admin` 不隐含业务数据读取、Task 执行或审批。`approver`、`auditor` 可被显式授予租户或项目范围；数据库触发器阻止其他角色跨越声明范围。自授角色与在线授予 `platform_admin` 被禁止。

### 2.4 幂等与并发

写接口要求 16–200 字符的可打印 ASCII `Idempotency-Key`。唯一范围是 tenant、可选 project、operation 和 key。

算法：

1. 对规范化请求体计算 SHA-256。
2. 获取 PostgreSQL transaction advisory lock。
3. 不存在记录时写入 `PROCESSING` 与租约。
4. 相同 key/相同 hash 且已完成时返回原响应。
5. 相同 key/不同 hash 返回冲突。
6. 过期记录原位回收，避免唯一索引形成永久阻塞。
7. 业务写入、审计和幂等完成响应在一个事务提交。

### 2.5 配置

配置采用 Tenant → Project → User 优先级。key 必须存在于代码中的受管 Schema，包含 password、secret、token、credential、api_key 或 private_key 的 key 一律拒绝。值必须是小于 64 KiB 的有效 JSON 并通过该 key 的类型/范围校验。

配置更新使用 advisory lock、行锁和 `expected_version` 乐观锁，避免并发覆盖。

### 2.6 审计和日志

审计事件包含 event、tenant、project、actor、action、resource、outcome、risk、request、trace、details 和时间。每个租户维护独立链头：

```text
entry_hash = SHA-256(previous_hash || canonical_event)
```

数据库触发器禁止 UPDATE/DELETE 审计事件；应用角色只能 SELECT/INSERT 审计事件。链头与实际最后事件 hash 每次写入前再次比对，异常时管理写入失败关闭。

请求日志采用字段白名单 JSON Formatter，只允许 request/trace、方法、路径、状态、耗时及主体 ID，不序列化 header 或 body。

## 3. 数据库变更

- `0002`：Organization、身份唯一约束、角色生命周期、配置表、RLS、应用角色。
- `0003`：租户/项目/双范围角色的数据库触发器约束。
- `0004`：撤销应用角色对 IAM/Control 表的物理 DELETE 权限。
- 每个迁移都有 down 文件；Compose migration runner 按顺序和 SHA-256 登记，变更已应用迁移会失败关闭。

## 4. API 与前端

P1 OpenAPI 发布 session、当前 tenant、organizations、projects、users、roles、role assignments、effective config 和 audit events。所有写接口声明 BearerAuth、`Idempotency-Key`、稳定错误码和响应模型；TypeScript DTO 从 OpenAPI 生成。

Web Console 增加 OIDC 边界、登录/回调/退出、项目上下文和企业访问页。前端只依据服务端 `/session` 裁剪菜单与查询；后端仍对每个接口独立授权。

## 5. 复杂度

设 token 长度为 `T`、有效角色/权限连接行数为 `R`、配置命中数为 `C`、分页大小为 `K`、审计 details 大小为 `D`：

- JWT 解析和签名输入处理：时间/空间 `O(T)`；JWKS key 查找由库缓存，网络刷新不计入纯算法复杂度。
- Principal 构建：数据库返回 `R` 行，时间 `O(R)`、空间 `O(R)`。
- 单次权限判断：哈希集合平均 `O(1)`。
- 配置合并：时间 `O(C)`、空间 `O(C)`。
- 幂等请求摘要：时间 `O(payload)`、摘要空间 `O(1)`。
- 审计 canonicalize/hash：时间 `O(D)`、空间 `O(D)`。
- 游标分页：应用处理 `O(K)`；数据库依赖 tenant/id 索引，避免 offset 线性扫描。

## 6. 测试策略

- 单元：OIDC 正负 claim、固定角色 allow/deny、生产配置失败关闭。
- 契约：19 个 OpenAPI operation、运行时投影、生成类型、四组 migration。
- PostgreSQL：两租户 RLS、应用最小权限、范围触发器、幂等回放/冲突/过期、角色即时撤销、配置覆盖、审计不可变。
- API 集成：真实 PostgreSQL + 签名 JWT，覆盖 session、创建、回放、只读拒绝、错误 audience/tenant。
- Keycloak：真实浏览器执行 Authorization Code + PKCE，再通过 JWKS 验签并验证 issuer/audience/tenant/sub。
- 前端：ESLint、TypeScript、Vitest、生产构建和 bundle budget。

聚合脚本为 `solve_p1_baseline.py`；默认只读，`--full` 执行本地质量门，`--postgres`、`--keycloak` 和 `--browser` 仅对显式提供的测试服务运行。

## 7. 安全边界与后续

P1 没有实现或启用模型调用、Agent 执行、网络探测、Sandbox 或漏洞验证。完整 Policy/Approval 与授权资产属于 P5，持久任务和服务身份属于 P3。只有这些安全边界分别验收后，才允许进入 P6 合成靶场验证。
