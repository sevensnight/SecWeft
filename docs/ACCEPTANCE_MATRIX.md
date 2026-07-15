# Legacy 单节点原型 2.1–2.17 行为矩阵（非企业验收）

> 本文件仅保存重构前单租户 SQLite 原型的行为证据。表内“完成”只表示在该旧口径下通过 characterization tests，**不得解释为企业级目标架构、P0 或最小企业版已经完成**。企业需求状态以 `architecture/01-requirements-capability-matrix.md` 和 `testing/p0-acceptance.md` 为准。P0 默认关闭旧执行、探测和沙箱能力。

验收口径是“单租户、明确授权、隔离靶场、非破坏性验证平台”。原需求文件只给出 2.1–2.17 的能力名称及风险判断，没有接口级 PRD；本矩阵将其补全为可执行验收项。

| ID | 交付实现 | 自动验收证据 | 结论 |
|---|---|---|---|
| 2.1 模型接口适配 | `ModelGateway` 统一 mock/OpenAI-compatible/Ollama；Provider 优先级、限流、三次失败熔断、逐 Provider failover | `test_model_message_schema_blocks_system_injection`；`solve_module2.py demo` | 完成 |
| 2.2 API 密钥动态配置 | 管理员热创建 Provider、用请求头轮换/清空 secret；Fernet 密文、HMAC 用户 Key、API 不回显、审计递归脱敏 | `test_provider_secret_is_encrypted_and_write_only`、`test_recursive_redaction_catches_secrets_in_values` | 完成 |
| 2.3 开源模型适配 | `ollama` 的 `/api/chat` 与通用 OpenAI-compatible `/chat/completions` | Provider schema/OpenAPI；mock 在无 GPU 环境完成回归 | 完成；性能依赖外部硬件 |
| 2.4 RESTful API | 31 个 API 资源路径、OpenAPI 3.1、严格 Pydantic schema、请求 ID、安全响应头、统一错误码 | `test_health_and_authentication`、`test_openapi_and_protocol_manifest` | 完成 |
| 2.5 主任务规划拆解 | 创建时生成 Scope→Probe→Evaluate→Report DAG；审批状态机、事件流、锁/并发上限、取消 | `test_task_plan_approval_execution_and_events` | 完成 |
| 2.6 安全漏洞利用验证 | 只生成 TCP/HTTP GET/HEAD 结构化步骤；漏洞信号必须命中显式 marker；合成 vulnerable/patched 靶场；结果明确“证据不等于可利用证明” | `test_vulnerable_and_patched_marker_comparison`；端到端 demo；Compose `lab` profile | 在安全验收边界内完成 |
| 2.7 自动资产探测 | 精确主机/CIDR、协议、端口、有效期、全局 allowlist 取交集；每次连接前解析并连接已校验 IP；低超时、串行探测 | `test_scope_rejects_wildcard_and_outside_port`、目标解析安全测试 | 在授权范围内完成 |
| 2.8 技能动态分配 | 六个内置技能；声明式 manifest 动态注册；风险级别、角色、input schema、启用标记；按 intent 可解释分配 | `test_openapi_and_protocol_manifest`；任务 plan 中 `assigned_skills` | 完成 |
| 2.9 上下文管理 | private/task 可见性、密钥清洗、token 估算、最后 12 条滚动摘要、结构化安全信封、checkpoint 恢复数据 | `test_task_context_checkpoint_preserves_security_envelope` | 完成 |
| 2.10 沙箱执行 | 默认 dry-run；local 仅开发；Docker 模式无网络、只读、非 root、drop ALL、no-new-privileges、CPU/RAM/PID/超时/输出限制；命令/参数白名单 | `test_sandbox_is_not_a_generic_shell`；Compose 安全参数 | 完成基础强隔离；不承诺绝对防逃逸 |
| 2.11 并发隔离/记忆共享 | 每任务状态、事件、锁、取消事件、对象所有权、临时工作区、记忆 namespace 和 visibility；全局 semaphore | `test_simultaneous_task_start_has_one_execution_side_effect`；跨用户对象 ACL 测试 | 单租户并发任务范围内完成 |
| 2.12 上下文协议元编程 | `/protocols/tools` 由技能数据库动态生成 schema；manifest 只描述工具，调用仍经过确定性策略 | `test_openapi_and_protocol_manifest` | 完成基线协议运行时 |
| 2.13 RAG | 文档来源、版本、分类、tags、hash；先 SQL ACL 过滤再评分；检索结果附 provenance 和 `untrusted_evidence_only` | `test_rag_acl_prefilter_and_provenance`、`test_rag_ingest_scrubs_secret` | 完成轻量基线 |
| 2.14 目标/代理/意图/指标配置 | `TargetProfile`；目标和代理各自绑定已批准 scope；intent 为三个防御枚举；scope hash 与任务审批绑定 | Scope/任务审批测试；Pydantic schema | 完成 |
| 2.15 日志全量追溯 | 资源变更、拒绝、模型调用、任务步骤、探测、沙箱、RAG、上下文均审计；递归脱敏；HMAC 链 | `test_audit_hash_chain_detects_tampering`、RBAC 拒绝审计测试 | 完成单机基线 |
| 2.16 Docker 一键部署 | 非 root API Dockerfile、健康检查、只读 Compose、持久卷、internal lab network、两个合成靶场 | `docker compose --profile lab config --quiet` | 完成 |
| 2.17 角色权限 | viewer/analyst/operator/admin 权限表；默认拒绝；对象所有权；Key 即时停用/角色更新；范围和任务创建/审批职责分离 | RBAC、自审批、跨用户对象访问、Key 撤销测试 | 完成 |

## 端到端验收流程

```text
管理员创建 analyst
  → analyst 创建精确 target scope
  → 管理员独立审批 scope
  → analyst 创建任务并得到有界 DAG
  → 管理员独立审批任务
  → operator/admin 执行
  → 每个网络步骤重新校验 scope 和解析 IP
  → 保存非破坏性证据与事件
  → 验证 HMAC 审计链
```

一条命令运行该流程：

```powershell
python solve_module2.py demo
```

## 明确不作为“完成”的错误口径

- 不把端口开放等同于漏洞真实可利用；
- 不把模型输出当授权、审批或策略判定；
- 不把普通 Docker 容器称为绝对防逃逸；
- 不承诺自动发现 0day、任意 CVE 自动生成稳定 EXP、防护绕过或隐蔽性优化；
- 不允许未经部署 allowlist 和独立审批的目标探测。
