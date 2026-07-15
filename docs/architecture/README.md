# P0 架构与工程基线文档索引

## 1. 文档目的

本目录定义“模块二：多模协同漏洞利用智能挖掘系统”的目标企业架构、演进边界和验收口径。它是后续 P1–P8 开发的上位约束，不代表相应业务能力已经实现。

P0 只完成架构、契约和工程基线，不开发、启用或验证具体漏洞利用能力。任何可能访问目标、执行命令或运行验证载荷的能力，都必须留到 P5/P6，并且只能在明确授权的白名单目标和隔离靶场中实现。

## 2. 状态术语

所有能力矩阵、里程碑和验收结果统一使用以下状态，禁止混用：

| 状态 | 含义 |
|---|---|
| `Legacy Implemented` | 旧单节点原型存在相应代码，但尚未满足目标企业边界 |
| `Legacy Verified` | 旧原型在其声明的单租户、SQLite、授权靶场范围内有实际测试证据 |
| `Planned` | 已完成目标设计，尚未落地代码或尚未执行验证 |
| `Implemented` | 目标架构下已有可运行实现，但尚未取得完整验收证据 |
| `Verified` | 目标架构下已运行规定的测试或检查，并保存可复核结果 |
| `Blocked` | 因明确的外部依赖缺失无法执行，并记录了未执行命令和影响范围 |

`Legacy Verified` 不能自动升级为 `Verified`。代码迁移后必须在新边界、新数据模型和新安全控制下重新测试。

## 3. 权威文档

| 文档 | 主要内容 |
|---|---|
| [00-current-state-assessment.md](00-current-state-assessment.md) | 旧原型事实、可复用能力和结构性差距 |
| [01-requirements-capability-matrix.md](01-requirements-capability-matrix.md) | 需求到服务、阶段、状态和证据的映射 |
| [02-system-context-and-service-boundaries.md](02-system-context-and-service-boundaries.md) | 系统上下文、信任区、服务边界和数据所有权 |
| [03-data-flows.md](03-data-flows.md) | 任务、模型、知识、上下文、沙箱、证据和审计数据流 |
| [04-domain-model-and-er.md](04-domain-model-and-er.md) | 聚合、核心实体、ER、数据约束和保留策略 |
| [05-task-state-machine.md](05-task-state-machine.md) | Task、Stage、Execution、Approval 状态机与并发约束 |
| [06-milestones.md](06-milestones.md) | P0–P8 顺序、入口条件、出口条件和禁止跨越项 |
| [07-risk-register.md](07-risk-register.md) | 风险、触发信号、责任阶段和规避方案 |
| [../security/rbac-permission-matrix.md](../security/rbac-permission-matrix.md) | 八类角色、数据范围和职责分离 |
| [../security/policy-and-approval-flow.md](../security/policy-and-approval-flow.md) | PDP/PEP、风险分级、多级审批和执行授权 |
| [../testing/strategy.md](../testing/strategy.md) | 分层测试、环境、证据与质量门 |
| [../testing/p0-acceptance.md](../testing/p0-acceptance.md) | P0 可执行验收清单 |
| [../testing/enterprise-mvp-acceptance.md](../testing/enterprise-mvp-acceptance.md) | 最小企业版本的最终验收口径 |

## 4. 不可变架构原则

1. 模型输出、RAG 文档、上下文和 Agent 记忆都不是授权来源。
2. 外部请求必须经身份认证、数据范围、RBAC/ABAC、策略、审批和审计门禁。
3. 高风险执行采用职责分离；创建者、审批者和执行者按风险级别相互隔离。
4. 服务只能写自己的数据库 schema，跨服务通过版本化 API 或事件交互。
5. Task 是持久化聚合；状态不能依赖进程内内存、单进程锁或未持久化队列。
6. 所有异步消费者必须支持重复投递、乱序防护、幂等和死信处理。
7. 所有命令和工具调用使用类型化参数，不接受任意 Shell 字符串。
8. Sandbox 默认无外部网络、非 root、只读根文件系统、资源受限，并运行于独立 Linux 执行节点。
9. 所有多租户业务数据显式携带 `tenant_id`；项目数据同时携带 `project_id`。
10. 真实 secret 不进入 Git、日志、异常、事件、URL、浏览器响应或普通业务表。
11. 审计、审批决定、执行尝试和证据采用追加语义，不覆盖历史记录。
12. P0 不开发漏洞验证；P6 也只允许合成靶场和明确授权的测试环境。

## 5. 决策冲突处理

当代码、旧 README、单项设计和本目录发生冲突时：

1. 已批准 ADR 优先于普通设计说明。
2. 安全硬拒绝规则优先于租户和项目配置。
3. 目标架构不能据旧原型的宽松行为降低安全要求。
4. 变更本目录中的关键边界、数据所有权或信任模型，必须新增或替代 ADR，不能静默修改。
