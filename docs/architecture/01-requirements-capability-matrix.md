# 需求拆解与能力矩阵

## 1. 使用规则

本矩阵用于回答四个问题：能力由谁负责、在哪个阶段实现、当前处于什么状态、用什么证据验收。

状态字段分别记录“旧原型状态”和“目标企业状态”。旧原型测试通过不能填入目标状态。

## 2. 核心业务能力

| 编号 | 能力 | 目标责任服务 | 首次实现阶段 | 旧原型状态 | 目标状态（P0） | 必需验收证据 |
|---|---|---|---|---|---|---|
| 2.1 | 统一模型接入、流式输出、路由、限流、熔断、成本 | model-gateway | P2 | Legacy Verified（窄范围） | Planned | Provider 契约测试、故障切换、流式、限流和成本测试 |
| 2.2 | API Key/凭据加密、隔离、轮换、吊销、Vault/KMS 接口 | model-gateway + secret manager | P2 | Legacy Verified（Fernet 单实例） | Planned | write-only API、轮换、撤销、跨租户和明文泄漏负向测试 |
| 2.3 | 开源模型注册、版本、端点、算力、健康、路由权重 | model-gateway | P2 | Legacy Implemented（有限适配） | Planned | 注册/健康/启停/权重和资源元数据集成测试 |
| 2.4 | 主任务规划、持久状态、暂停恢复、取消重试、补偿 | control-plane | P3 | Legacy Verified（单进程） | Planned | PostgreSQL 状态机、多副本竞态、重启恢复和幂等测试 |
| 2.5 | 多 Agent 编排、职责、Schema、工具、预算和审计 | agent-orchestrator | P3 | Legacy Implemented | Planned | Agent/Skill/Workflow 契约、预算、超时、循环上限测试 |
| 2.6 | Skill 注册、版本、灰度、权限、统计和失败分析 | agent-orchestrator | P3 | Legacy Verified（基础注册） | Planned | 版本兼容、启停、灰度、权限、统计测试 |
| 2.7 | 上下文压缩、快照、恢复、记忆和污染检测 | context-service | P4 | Legacy Verified（单任务） | Planned | 租户/项目隔离、压缩、快照恢复、secret/污染测试 |
| 2.8 | 多知识库、文档版本、混合检索、重排、引用 | knowledge-service | P4 | Legacy Verified（轻量检索） | Planned | ACL 前置过滤、版本、增量索引、引用溯源测试 |
| 2.9 | 授权资产、白名单、CIDR、仓库目录、时间窗、工具和速率 | asset-service | P5 | Legacy Verified（目标/端口） | Planned | 授权文档、范围 digest、DNS、时间窗、跨租户负向测试 |
| 2.10 | 候选、验证计划、风险预检、审批、证据和人工复核 | validation-service | P6 | Legacy Verified（合成信号） | Planned；P0 禁止实现 | 仅授权合成靶场 E2E、patched 对照、证据复核测试 |
| 2.11 | Sandbox 模板、实例、配额、网络、快照、销毁和回收 | sandbox-service | P5 | Legacy Verified（受限 runner） | Planned；P0 不执行载荷 | 隔离、默认无网、资源耗尽、异常回收和逃逸防护测试 |
| 2.12 | 队列、优先级、租户配额、分布式锁、幂等、DLQ | control-plane + NATS/Redis/PostgreSQL | P3 | Legacy Implemented（进程内） | Planned | 重复/乱序消息、多副本、fencing、DLQ 和配额测试 |
| 2.13 | Tool/Skill/Agent/Workflow/Policy/Result/Evidence 协议 | api-contracts | P0/P3 | Legacy Implemented（部分 Schema） | Implemented（P0 版本化 Schema 基线；P3 运行时待实现） | OpenAPI/JSON Schema lint、兼容性和生成代码检查 |
| 2.14 | Policy Engine、多级审批、明确拒绝原因 | control-plane + policy-engine | P1/P5 | Legacy Verified（双人基础） | Designed（P0 流程与信任边界；P1/P5 执行面待实现） | deny-overrides、职责分离、撤销、过期和 TOCTOU 测试 |
| 2.15 | 全量日志、追加审计、trace、脱敏和完整性 | audit-service + observability | P1 | Legacy Verified（单库 hash chain） | Planned | 必记事件覆盖、篡改检测、脱敏和外部锚定测试 |
| 2.16 | Compose 一键开发、初始化、迁移、备份恢复、K8s/Helm | infrastructure | P0/P8 | Legacy Verified（单 API Compose） | Implemented（P0 本地平台基线；P8 生产化待实现） | Compose health、迁移、备份恢复、Helm lint/render |
| 2.17 | 八类角色、菜单/API/数据/模型/技能/资产/审批/导出权限 | control-plane + api-gateway | P1 | Legacy Verified（四角色） | Designed（P0 权限矩阵；P1 后端执行待实现） | 后端权限矩阵、跨租户、对象越权和职责分离测试 |

## 3. 横切能力

| 能力域 | 目标输出 | 责任位置 | 阶段 | P0 状态 | 验收证据 |
|---|---|---|---|---|---|
| 企业前端 | React/TS/Vite、领域模块、权限裁剪、i18n、深色模式 | `apps/web-console` | P7 | Implemented（P0 可运行壳层与性能基线；P7 全业务页面待实现） | Vitest、Storybook、Playwright、bundle budget |
| API First | 静态 OpenAPI、错误/分页/幂等/追踪规范、生成 SDK | `packages/api-contracts` | P0 | Implemented | OpenAPI 语义快照、runtime 投影、生成无差异 |
| 事件契约 | 版本化命令/事件、CloudEvents 信封 | `packages/api-contracts/events` | P0 | Implemented | Draft 2020-12 Schema 校验、正负契约测试 |
| 多租户数据 | tenant/project、RLS、repository scope、缓存/对象命名空间 | control-plane + 各服务 | P1 | Planned | 数据库 RLS 与跨租户负向测试 |
| 配置 | 默认/环境/部署/租户/项目/用户分层和 Schema | `packages/config` + control-plane | P1 | Planned | 配置优先级、非法配置和 secret 检查 |
| 可观测性 | 日志、指标、trace、健康/就绪、成本与资源 | infrastructure/monitoring + 目标 `packages/observability` | P0/P8 | Implemented（P0 OTel/Prometheus 基线；P8 全链路待实现） | trace 贯通、指标存在性、敏感字段测试 |
| DevSecOps | 格式、静态、类型、测试、扫描、SBOM、签名、发布审批 | CI/infrastructure | P0/P8 | Implemented（P0 工作流与本地门禁；远端发布证明待仓库接入） | 流水线实际执行记录和制品证明 |
| 数据保留 | 在线保留、归档、法务保留、销毁和 WORM | 各数据所有者 | P0/P8 | Designed（P0 责任与策略；P8 归档执行待实现） | 保留策略测试、归档/恢复、不可变审计证明 |
| 故障恢复 | 重试、补偿、DLQ、备份恢复、RPO/RTO | 各服务 + infrastructure | P3/P8 | Implemented（P0 备份恢复基线；P3/P8 故障注入待实现） | 故障注入、恢复演练和数据核对 |

## 4. P0 必须交付的设计能力

| P0 产物 | 对应文档 | 完成判据 |
|---|---|---|
| 需求拆解与能力矩阵 | 本文件 | 每项能力均有唯一责任、阶段和证据 |
| 系统边界与服务划分 | `02-system-context-and-service-boundaries.md` | 不存在双重数据所有者或隐式跨库访问 |
| 数据流 | `03-data-flows.md` | 所有高风险路径均经过策略、审批、审计和 Sandbox |
| 领域模型与 ER | `04-domain-model-and-er.md` | 多租户、版本、追加实体和保留策略明确 |
| 任务状态机 | `05-task-state-machine.md` | 暂停、恢复、取消、重试、超时、补偿和审批均有合法迁移 |
| 权限矩阵 | `../security/rbac-permission-matrix.md` | 八类角色、数据范围和 SoD 明确 |
| 策略审批 | `../security/policy-and-approval-flow.md` | deny-overrides、digest 绑定和执行前重验明确 |
| 风险与阶段 | `06-milestones.md`、`07-risk-register.md` | 每项高风险有责任阶段和门禁 |
| API/事件基线 | `packages/api-contracts/openapi`、`packages/api-contracts/events` | 真实契约 lint，不以运行时生成替代 |
| 工程骨架 | Monorepo、Compose、开发文档 | 可在干净环境执行构建和 smoke |

## 5. 安全否决条件

出现以下任一情况，P0 不得验收：

- 将旧原型的 41 项测试描述为目标企业架构测试全部通过。
- P0 新增真实扫描、漏洞 payload、任意命令或互联网目标能力。
- 新服务直接访问其他服务的数据库表。
- 用内存锁作为多副本任务唯一并发控制。
- `admin` 继续作为所有业务权限的通配符。
- OpenAPI 只依赖运行时导出，没有版本化契约文件。
- 事件消费者没有幂等键和重复投递策略。
- 任何 secret 出现在 Git、URL、响应、日志或事件示例中。
