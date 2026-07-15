# 风险登记册

## 1. 评分规则

概率和影响使用 1–5 分，固有风险为二者乘积：`15–25 严重`、`8–14 高`、`4–7 中`、`1–3 低`。残余风险必须在对应阶段退出评审时重新评分，不能因文档存在自动降低。

## 2. 风险清单

| ID | 风险 | 概率 | 影响 | 固有级别 | 触发/监测信号 | 主要控制 | 责任阶段 | 目标残余风险 |
|---|---|---:|---:|---:|---|---|---|---|
| R-01 | 把旧原型测试通过误报为企业级完成 | 4 | 5 | 严重 | README/报告不区分 Legacy 与 Target | 统一状态术语、能力矩阵、证据链接、发布审核 | P0 | 中 |
| R-02 | 大爆炸重写导致安全算法和回归丢失 | 4 | 5 | 严重 | 大量文件一次替换、旧测试被删除 | characterization tests、逐上下文提取、兼容窗口、ADR | P0–P4 | 中 |
| R-03 | 仅创建空目录/固定成功端点形成“假微服务” | 4 | 4 | 严重 | health 以外业务返回固定值、无数据所有权 | 骨架只做真实连接/契约 smoke，能力仍标 Planned | P0 | 低 |
| R-04 | 跨租户或跨项目数据泄漏 | 3 | 5 | 严重 | 查询缺 tenant_id、缓存 key 无命名空间 | RLS、scoped repository、对象前缀、负向测试 | P1 | 低/中 |
| R-05 | 通配管理员绕过职责分离 | 4 | 5 | 严重 | `admin=*`、管理员自审 | 显式权限、数据范围、actor ID SoD、无业务超级用户 | P1 | 低 |
| R-06 | 重复/乱序消息产生重复副作用 | 4 | 5 | 严重 | 同一任务多次 SandboxRun、版本回退 | outbox/inbox、event_id、aggregate_version、幂等键 | P3/P5 | 低/中 |
| R-07 | Worker 丢失与迟到写造成状态覆盖 | 3 | 5 | 严重 | 两 worker 同时提交、旧结果覆盖新结果 | 租约、单调 fencing token、乐观锁、attempt 追加 | P3 | 低/中 |
| R-08 | 审批后 Scope/Plan/Policy 被替换 | 3 | 5 | 严重 | 执行参数与审批快照不一致 | 不可变 revision、digest 绑定、短期 grant、执行点重验 | P1/P5 | 低 |
| R-09 | 审批撤销或过期后任务仍执行 | 3 | 5 | 严重 | revoked grant 产生新 Run | nonce、expiry、撤销投影、运行中取消、负向测试 | P5 | 低 |
| R-10 | Sandbox 逃逸或污染宿主机 | 3 | 5 | 严重 | 特权容器、Docker Socket、HostNetwork | 独立 Linux worker、gVisor、非 root、只读、seccomp/MAC、无 socket | P5/P8 | 中 |
| R-11 | SSRF、DNS rebinding 或代理绕过 Scope | 4 | 5 | 严重 | 校验 hostname 后再次解析、重定向到越界地址 | URL 规范化、全 A/AAAA 校验、连接已验证 IP、禁自动重定向 | P5/P6 | 低/中 |
| R-12 | 模型/RAG prompt injection 扩大权限 | 4 | 5 | 严重 | 文档指令触发未注册工具 | untrusted 标签、类型化工具、PEP/PDP、系统提示隔离 | P3/P4 | 中 |
| R-13 | Secret 泄漏到 DB、事件、日志或响应 | 3 | 5 | 严重 | secret scan 命中、异常回显 key | Vault/KMS reference、write-only、落库前脱敏、canary 测试 | P1/P2 | 低/中 |
| R-14 | 审计数据库和密钥被整体替换 | 2 | 5 | 高 | 链在单库自洽但外部无锚点 | 独立权限、hash chain、周期 WORM/Object Lock 锚定 | P1/P8 | 低/中 |
| R-15 | Evidence 不可复核或结论由字符串命中替代 | 3 | 5 | 严重 | 无 artifact hash/对照/版本/日志 | 多条件成功规则、patched 对照、chain metadata、人工 Review | P6 | 低/中 |
| R-16 | 数据组件过多导致运维失控 | 4 | 3 | 高 | 同类数据库重复、无容量依据 | MVP PostgreSQL+pgvector/FTS、Redis、NATS、MinIO；按 ADR 扩展 | P0/P8 | 低 |
| R-17 | OpenAPI/事件和实现漂移 | 4 | 4 | 严重 | 手写重复 DTO、前端运行时错误 | API First、生成 SDK、契约测试、breaking-change gate | P0–P8 | 低 |
| R-18 | Windows 开发结果无法代表 Linux Sandbox | 4 | 4 | 严重 | 本地通过但 seccomp/MAC 未运行 | Linux CI/worker、容器/节点集成测试、平台差异文档 | P5/P8 | 中 |
| R-19 | 模型供应商不稳定或成本失控 | 4 | 3 | 高 | 超时/429、Token/费用异常 | 配额、预算、限流、熔断、主备、成本告警 | P2/P8 | 低/中 |
| R-20 | 对象、索引和数据库删除不一致 | 3 | 4 | 高 | tombstone 后仍可检索或下载 | 删除工作流、outbox、重试/DLQ、定期 reconciliation | P4/P8 | 低/中 |
| R-21 | 迁移不可回滚或多版本不兼容 | 3 | 5 | 严重 | 部署后旧实例失败、数据截断 | expand/contract、up/down、快照恢复、兼容窗口 | P0–P8 | 低/中 |
| R-22 | 没有 Git 基线导致变更不可审计 | 4 | 4 | 严重 | 无 `.git`、无法定位变更来源 | 工作区快照、初始化 Git、原子提交和分支规范 | P0 | 低 |
| R-23 | 审计或对象存储故障时高风险执行继续 | 3 | 5 | 严重 | 无审计记录的 SandboxRun | 本地审计 outbox 原子写；无法持久化则 fail closed | P1/P5 | 低 |
| R-24 | 测试环境使用真实目标或真实凭据 | 2 | 5 | 高 | CI 中出现生产地址/key | 合成目标、Mock、secret scanning、测试网络 allowlist | P0–P8 | 低 |
| R-25 | P0 越界开发漏洞验证 | 3 | 5 | 严重 | 新增 payload/探测器/外网访问 | P0 代码审查否决、Compose 默认闭网、验收扫描 | P0 | 低 |

## 3. 风险评审机制

- 每个阶段开始时确认责任人和控制是否可实现。
- 每个阶段结束时记录测试证据和残余评分。
- 严重风险未降低到批准阈值时不得进入依赖该控制的阶段。
- 新增外部网络、执行器、数据导出、模型供应商或高分类数据时必须新增风险评审。
- 风险接受必须有范围、期限、批准人和补偿控制，不能用“开发环境”永久豁免。

## 4. P0 重点监控

P0 退出前必须关闭或显式降级以下风险：R-01、R-03、R-17、R-22、R-24、R-25。其余风险必须有阶段责任和可测试控制，不能留空。
