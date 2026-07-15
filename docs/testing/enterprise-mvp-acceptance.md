# 企业 MVP 最终验收标准

## 1. 当前结论与适用时点

本文是 P8 发布门禁，不是 P0 完成声明。截至 2026-07-11，系统只处于 P0 工程基线，**不具备企业 MVP 验收资格**。P1–P7 的身份、多租户、模型、持久编排、知识/上下文、授权 Sandbox、受控验证和完整前端均需按阶段完成后，才能执行本验收。

验收对象必须是一个固定 commit、固定 lockfile、固定容器 digest、固定 Helm values 和明确环境；不能混用开发机测试、设计文档和未运行脚本拼接“通过”。

## 2. 一票否决项

出现任一项即拒绝发布：

- 能跨 tenant/project 读取、修改、检索、导出或订阅数据；
- 模型、RAG、Agent 或前端能绕过 RBAC/Policy/Approval；
- 未授权、过期、撤销或 digest 不匹配仍能创建 SandboxRun；
- Sandbox 可访问 Docker Socket、宿主敏感路径、未授权网络或超出资源配额；
- secret 出现在响应、日志、事件、对象 metadata、前端存储、镜像或代码仓库；
- 审计不可持久化时高风险执行仍继续；
- 证据 hash/来源不可复核，或把端口开放、模型文本、单一 marker 当作漏洞成立；
- 备份不能恢复、滚动升级不能回滚、关键 SLO 未达标；
- 存在未解释的严重/高危依赖、镜像、IaC 或应用漏洞；
- 对未授权真实目标、互联网或客户环境运行验证。

## 3. 功能验收

| 领域 | 最低可验收能力 | 必要证据 |
|---|---|---|
| IAM/租户 | OIDC、用户/服务身份、Tenant/Org/Project、八角色、成员生命周期 | 正常与跨租户负向 E2E |
| 配置/凭据 | 平台→租户→项目配置、CredentialRef、轮换/撤销、write-only | secret canary、KMS/Vault 审计 |
| 模型网关 | Provider/Model、结构化/流式/工具调用、限流、熔断、主备、成本 | Mock + 受控 Provider 契约/故障测试 |
| Agent/任务 | 版本化 Agent/Skill/Workflow、持久状态机、暂停恢复取消重试 | 多副本、重启、重复/乱序、fencing 测试 |
| Context/知识 | Snapshot/Memory、ACL 前置检索、版本、引用、删除重建 | 污染/越权负向、引用和恢复核对 |
| Asset/Scope | 授权文档、目标/端口/时间/工具、DNS/代理重验 | SSRF/rebinding/重定向/过期拒绝 |
| Policy/Approval | R0–R4、obligations、多级审批、SoD、grant | 自审、撤销、重放、digest 变化拒绝 |
| Sandbox | 独立 Linux worker、模板/实例/配额/网络/回收 | seccomp/MAC/gVisor、外网/宿主拒绝、故障回收 |
| Validation/Evidence | Candidate/Plan、静态预检、合成对照、Evidence/Review | vulnerable/patched 对照、artifact hash、人工复核 |
| Audit/Report | 追加审计、外部锚定、来源可追踪报告、受控导出 | 篡改检测、导出审批、报告引用核对 |
| Web Console | 领域页面、错误/空态、SSE、权限裁剪、i18n、主题 | Playwright、a11y、浏览器矩阵、bundle |

## 4. 安全与合规验收

必须完成：威胁建模、SAST、依赖/许可证、secret、容器、IaC、DAST、API fuzz、租户隔离、权限矩阵、SSRF、文件上传、prompt injection、安全日志和 Sandbox 红队测试。所有发现按严重度、责任人、修复版本和复测证据闭环。

审计事件至少关联 tenant/project、actor、action、resource、outcome、risk、request/trace、task/agent/sandbox、duration、前序 hash；周期锚定到独立 WORM/Object Lock 存储。普通管理员不能修改/删除历史或读取业务 secret。

数据分类、保留、删除、法律冻结、导出和备份必须在数据库、对象、索引、缓存和日志间一致。删除工作流失败进入 DLQ/reconciliation，不能只删主表。

## 5. 可靠性、性能和容量

发布前由产品 SLO 文档给出具体目标，至少覆盖：

- API 可用性、读写 p95/p99、错误率；
- Task 提交到排队、Stage 调度、SSE 延迟和恢复时间；
- 模型首 Token/完成延迟、429/5xx 和成本上限；
- 知识检索延迟、召回质量和 ACL 过滤成本；
- Sandbox 创建/回收时延、并发、资源和队列背压；
- Evidence/Report 生成时间和对象吞吐；
- 数据规模、租户数、并发用户、Task/事件/日志保留容量。

测试包含峰值、两倍预期突发、至少一次长稳、冷启动和容量极限。报告保存 workload、硬件/集群、数据规模、版本、原始结果和统计方法；只给平均值不通过。

故障注入覆盖 API/worker 重启、节点丢失、NATS 重复/分区、PostgreSQL failover、Redis 丢失、MinIO 超时、模型 429/5xx、OTel 后端中断和网络延迟。恢复后不丢持久 Task/Evidence/Audit，不重复高风险副作用，旧 fencing token 无法写入。

## 6. 部署、升级和灾备

| 项目 | 通过标准 |
|---|---|
| Docker | 非 root、只读、最小 capability、health/readiness、digest 固定 |
| Kubernetes/Helm | namespace/RBAC、NetworkPolicy、PDB、资源、探针、HPA、Pod Security、Secret 引用 |
| 供应链 | 可重现构建、SBOM、签名、provenance、部署时验签 |
| 数据迁移 | expand/migrate/contract，滚动新旧实例兼容，数据核对 |
| 回滚 | 应用和配置可回滚；数据按 migration/备份方案恢复 |
| 备份恢复 | 加密、跨故障域、定期恢复，实测 RPO/RTO 达标 |
| 可观测 | dashboard、SLO、告警路由、runbook，演练能触发和关闭 |

生产部署禁止使用 Compose `.env` 作为 secret 管理，禁止暴露数据库/消息/MinIO 管理面，禁止 API 或 Sandbox 挂 Docker Socket。

## 7. 前端体验与可访问性

- 支持明确版本的 Chrome/Edge/Firefox，关键流程无控制台错误。
- 路由级分包、虚拟列表、Web Worker、缓存和 bundle budget 通过；性能预算包含首屏、交互和大列表。
- SSE 断线续传、重复去重、权限撤销、会话过期和网络错误有可理解状态。
- 键盘导航、焦点、语义标签、颜色对比和屏幕阅读器满足 WCAG 2.2 AA 目标。
- 中英文、深浅主题、时区和长文本布局通过视觉回归。
- 前端不持久化 access token/API key，不把权限隐藏当后端授权。

## 8. 阶段准入

| 阶段 | 进入下一阶段前必须完成 |
|---|---|
| P1 | OIDC、多租户、RBAC/ABAC、Policy/Approval、审计负向矩阵 |
| P2 | Provider 凭据、协议、故障和成本门禁 |
| P3 | 持久任务、多副本、幂等、租约/fencing、SSE 恢复 |
| P4 | Context/知识 ACL、污染、引用、删除重建 |
| P5 | Authorization Scope 与 Linux Sandbox 隔离独立验收 |
| P6 | 只在合成靶场完成 Evidence/Review/Report 闭环 |
| P7 | 生成 SDK 驱动的全领域 UI、E2E、a11y、性能预算 |
| P8 | 本文全部功能、安全、SLO、部署、灾备和供应链证据 |

任何阶段的设计完成不等于测试通过；阻断控制不得顺延到依赖它的危险能力之后。

## 9. 最终执行入口与证据包

P0 当前真实入口是：

```powershell
task check
```

在 P8 开始前，仓库必须提供并在 CI/隔离验收环境实现统一入口 `task acceptance:enterprise`，其内部调用现有 P0 门禁以及 P1–P8 的 integration、security、e2e、performance、chaos、backup-restore、upgrade-rollback、sbom/signature 检查。该入口尚不存在，因此当前不能运行或宣称最终验收。

最终证据包至少包含：commit/tag、镜像 digest、Helm values hash、依赖 lock hash、环境 manifest、JUnit/覆盖率、Playwright/可访问性、性能原始结果、安全报告、SBOM/签名、migration/数据核对、备份恢复、故障演练、风险接受和审批签字。证据必须存入只读制品库并按版本可追溯。

## 10. 签署条件

产品负责人确认范围和 SLO；架构负责人确认边界和兼容；安全负责人确认威胁/漏洞/Sandbox/授权；运维负责人确认可观测、升级、回滚和灾备；质量负责人确认测试证据。所有一票否决项为零且风险接受有范围、期限和补偿控制后，才可标记“企业 MVP Accepted”。
