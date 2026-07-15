# RBAC、数据范围与职责分离矩阵

## 1. 授权模型

系统采用 RBAC + ABAC：

- RBAC 决定主体是否具有某类动作权限。
- ABAC 根据 tenant、project、organization、资源所有权、数据分类、风险、时间、Scope、审批和运行时事实收紧权限。
- Policy Engine 可以拒绝或要求审批，但不能为主体创造其本来没有的 RBAC 权限。
- 前端菜单和按钮裁剪只改善体验，不构成安全控制；每个后端入口和异步消费者都必须重新检查。

禁止 `admin=*`。平台管理员负责平台运维，不默认拥有租户业务内容读取、任务执行或审批权限。

## 2. 标准角色

| 角色 | 角色代码 | 主要职责 | 默认数据范围 |
|---|---|---|---|
| 平台管理员 | `platform_admin` | 租户生命周期、平台配置、全局模板和服务运行 | 全局运维元数据；默认不读租户 Restricted 内容 |
| 租户管理员 | `tenant_admin` | 租户成员、角色、组织、项目和租户配置 | 指定 tenant |
| 项目管理员 | `project_admin` | 项目成员、项目配置、资产和工作流绑定 | 指定 project |
| 安全研究员 | `security_researcher` | 分析、候选、验证计划草稿、知识维护 | 授权 project |
| 任务操作员 | `task_operator` | 对已批准任务执行、暂停、恢复、取消 | 授权 project 和 Task |
| 审批员 | `approver` | 审批/拒绝/撤销 Scope、计划、导出和高风险操作 | 被分配的 tenant/project/approval group |
| 审计员 | `auditor` | 读取审计、策略决定、审批和导出审计证据 | 被分配 tenant/project；只读 |
| 只读用户 | `readonly_user` | 查看允许的数据和结果 | 被分配 project，受 classification ACL |

角色可以叠加，但职责分离按用户 ID、对象创建关系和审批链判断。用户同时拥有 `security_researcher` 和 `approver` 也不能审批自己的计划。

## 3. 权限命名

权限代码采用 `<resource>.<action>`：

```text
tenant.read|create|update|suspend
membership.read|invite|update|revoke
role.read|assign|revoke
project.read|create|update|archive
credential.create|rotate|revoke|metadata.read
model.read|manage|invoke
agent.read|draft|publish|bind
skill.read|draft|publish|bind
workflow.read|draft|publish|bind
knowledge.read|ingest|update|delete|reindex
asset.read|create|update|archive
scope.read|draft|submit|approve|reject|revoke
task.read|create|update_draft|submit|execute|pause|resume|cancel|retry
candidate.read|create|update
validation_plan.read|draft|submit|approve|reject|revoke
sandbox_template.read|publish|bind
sandbox_run.read|execute|cancel
policy.read|publish|bind
approval.read|decide|revoke
audit.read|export
report.read|generate|export
system_config.read|update
```

审批、执行和导出权限不隐含在普通 `update` 中。

## 4. 能力矩阵

符号：`G/T/P/O` 分别表示全局、租户、项目、本人/本人创建对象范围；`R` 读取、`C` 创建、`M` 管理、`E` 执行、`A` 审批、`X` 导出。

| 能力 | 平台管理员 | 租户管理员 | 项目管理员 | 安全研究员 | 任务操作员 | 审批员 | 审计员 | 只读用户 |
|---|---|---|---|---|---|---|---|---|
| 平台配置/运行元数据 | M(G) | R(T) | - | - | - | - | R(G) | - |
| 租户生命周期 | M(G) | R(T) | - | - | - | - | R(G) | - |
| 组织、成员、角色 | R(G) | M(T) | M(P) | R(O) | R(O) | R(O) | R(T/P) | R(O) |
| 项目与项目配置 | R(G) | M(T) | M(P) | R(P) | R(P) | R(P) | R(P) | R(P) |
| 模型供应商/实例 | M(G) | M(T) | 绑定(P) | R/调用(P) | R/调用(P) | R(P) | R(元数据) | R(P) |
| 凭据 | 写入/轮换(G)，不可读 | 写入/轮换(T)，不可读 | 绑定(P)，不可读 | - | - | - | R(元数据) | - |
| Agent/Skill/Workflow | 发布(G) | 发布(T) | M/绑定(P) | 草拟(P) | 使用(P) | R(P) | R(元数据) | R(P) |
| 知识库 | R(运维元数据) | M(T) | M(P) | C/M(P) | R(P) | 按审批需要 R | R(元数据) | 按 ACL R(P) |
| 资产 | R(运维元数据) | M(T) | M(P) | C/M(P) | R(P) | R(P) | R(P) | R(P) |
| Authorization Scope | R(元数据) | M(T) | M/提交(P) | 草拟/提交(P) | R(P) | A/拒绝/撤销(P) | R(P) | R(P) |
| Task 草稿/提交 | R(元数据) | R(T) | C/M/提交(P) | C/编辑草稿/提交(P) | C/提交(P) | R(P) | R(P) | R(P) |
| Task 执行控制 | - | - | R(P) | R(P) | E/暂停/恢复/取消/重试(P) | A/撤销(P) | R(P) | R(P) |
| Candidate/ValidationPlan | - | R(T) | M(P) | C/M 草稿/提交(P) | R(P) | A/拒绝/撤销(P) | R(P) | R(P) |
| Sandbox Template | 发布(G) | 绑定(T) | 选择/绑定(P) | R(P) | R(P) | R(P) | R(元数据) | R(P) |
| Sandbox Run | - | - | R(P) | R(P) | 仅凭有效 grant 执行/取消 | R(P) | R(P) | R(P) |
| Policy | 发布平台硬规则 | 发布仅收紧(T) | 发布仅收紧(P) | R(P) | R(P) | R(P) | R(T/P) | R(P) |
| Approval | - | R(T) | R(P) | R(本人请求) | R(P) | 决定/撤销(分配范围) | R(P) | R(P) |
| Audit | R(平台运维) | R(T) | R(P) | R(自身) | R(自身) | R(审批相关) | R/X(T/P) | - |
| Report | R(元数据) | R/X(T) | R/X(P) | R/X(P，需导出策略) | R(P) | R(P) | R/X(T/P) | R(P) |

矩阵表达默认角色包。最终允许结果还必须经过数据范围和策略判断。

## 5. 数据范围解析

请求的数据范围由服务端计算：

1. 从经过验证的 OIDC `iss/sub` 找到 UserIdentity。
2. 读取当前有效 Membership 和 RoleAssignment。
3. 根据 URL 资源 ID 从数据库取得真实 `tenant_id/project_id`。
4. 求角色范围、资源范围、classification ACL 和策略约束的交集。
5. 将确定的 scope 注入 repository 查询；不得让调用方传入任意 tenant 条件。

项目查询基线：

```sql
SELECT ...
FROM project_resource
WHERE tenant_id = :authorized_tenant
  AND project_id = ANY(:authorized_projects)
  AND id = :resource_id;
```

未命中应优先返回 `404` 避免泄露对象存在性；明确权限管理接口可返回 `403`，并始终记录拒绝审计。

## 6. 职责分离

| 风险/对象 | 必须分离的身份 |
|---|---|
| Scope | 创建/提交者不能审批自己的 Scope |
| 中风险 ValidationPlan | 计划创建者与审批者不同 |
| 高风险 ValidationPlan | 创建者、两个审批人相互不同；执行人不能是审批人 |
| Task | 创建者不能审批其高风险执行；执行者不能作为该次审批人 |
| Policy | 作者不能独自发布降低限制的版本；子级永远不能降低上级硬规则 |
| Credential | 创建/轮换者无法读取 secret；审计员只能读元数据 |
| Report Export | 报告作者不能单独批准 Restricted 数据外发 |
| Audit | 业务管理员不能修改、删除或伪造 AuditEvent |

SoD 检查使用稳定用户 ID，不使用显示名、角色名或会话 ID。

## 7. 角色和权限生命周期

- RoleAssignment 必须记录授予者、理由、范围、开始/结束时间和版本。
- 角色撤销即时影响新请求；长期任务在下一个 Stage、恢复和执行前重新检查。
- 高风险任务运行期间角色撤销触发策略重评，必要时取消。
- 禁止服务启动时无条件重置管理员角色或密钥。
- 首次管理员初始化采用一次性引导流程，完成后禁用 bootstrap token。

## 8. 平台运维与 Break-glass

平台管理员默认不读取租户 Restricted 内容。Break-glass 仅用于平台故障处置，不得用于漏洞验证或绕过禁止操作，并满足：

- 默认关闭，MVP 可完全不实现。
- 强认证、明确 incident、最短有效期、双人批准。
- 只授予必要的临时只读或运维权限。
- 全量记录、实时告警、事后复核和自动撤销。
- 无法绕过 R4 永久禁止规则。

## 9. 后端与前端执行要求

### 后端

- 每个 Controller/handler 声明 permission code，但数据范围必须在 application/domain 层再次约束。
- 消息消费者使用服务身份，并验证 command 中的 tenant/project/aggregate 引用。
- Repository 默认要求 TenantContext；不存在无 scope 的普通查询方法。
- 对拒绝返回稳定错误码、matched policy IDs 和安全化原因。

### 前端

- 菜单、路由、按钮根据服务器返回的 effective permissions 裁剪。
- 不在浏览器推导高风险授权，不缓存 secret 或 ExecutionGrant。
- 权限变化后清理 Query cache 并重新加载会话。
- 直接调用隐藏接口仍应被后端拒绝，Playwright 必须覆盖此场景。

## 10. 权限验收

- 八个角色的允许/拒绝矩阵有自动化参数测试。
- 任意资源 ID 替换不能跨 tenant/project 读取。
- 平台管理员不能默认读取租户 Restricted 文档或执行 Task。
- 多角色用户不能审批自己的 Scope/Plan/Task。
- 角色撤销后，新请求立即失败，运行任务在下一个安全边界重评。
- 前端隐藏按钮与直接 API 调用都被分别测试。
- 每次拒绝和权限变更包含 tenant、actor、permission、resource、result 和 trace。
