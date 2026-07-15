# ADR-0003：集中策略决策、分布式执行点复验

- 状态：Accepted
- 日期：2026-07-10
- 决策范围：权限、策略、审批和高风险执行

## 背景

任务从 API 经 Orchestrator、Validation 到 Sandbox，审批和执行之间可能相隔数小时。仅在 API 入口检查一次会出现 TOCTOU；让每个服务独立解释策略又会造成规则漂移。模型和 RAG 不能作为授权来源。

## 决策

1. Control Plane 是 Policy Decision Point，保存版本化 Policy、Decision 和 Approval。
2. `packages/policy-engine` 是确定性、无 I/O 的规则计算库。
3. Gateway、Orchestrator、Validation、Sandbox、Report Export 均为 Policy Enforcement Point。
4. PDP 使用 deny-overrides；子级策略只能收紧父级。
5. 高风险审批绑定 Scope、Plan、Policy 和工具版本 digest。
6. 审批完成签发短期、最小权限、一次性的内部 ExecutionGrant。
7. 最终 PEP 验证 grant，并重验当前权限、撤销、时间、DNS/IP、网络和资源事实。
8. R4 永久禁止行为没有管理员绕过或 break-glass。

## 备选方案

### 只在 API Gateway 鉴权

拒绝。异步任务、消息和执行点可在授权变化后继续运行。

### 每个服务维护独立策略

拒绝。语义漂移，拒绝原因不可统一，难以审计。

### 审批后保存 `approved=true`

拒绝。无法绑定参数版本、撤销、过期和一次性执行。

### 让模型决定是否允许执行

拒绝。模型输出非确定、可被注入且不可作为安全边界。

## 结果

正面结果：策略语义统一；执行点仍能阻止 TOCTOU；审批可复核；拒绝原因稳定。

负面结果：需要签名密钥管理、撤销投影和多处 PEP 契约测试；策略可用性成为关键依赖。

## 约束

- RBAC 权限缺失时 Policy 不能提升权限。
- grant 不返回浏览器、不进入日志或普通事件。
- digest 任一变化使审批和 grant 失效。
- 无法持久化审计 outbox 时高风险操作失败关闭。

## 验证

- 平台 DENY 无法被租户/项目覆盖。
- 创建者、审批者、执行者职责分离自动测试。
- 过期、撤销、重复 nonce、digest/目标/工具不匹配全部拒绝。
- P0 仅验证决策和状态，不访问目标或执行验证。
