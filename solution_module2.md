# 模块二完整题解与实现说明

## 1. 问题分析

输入文件给出的任务是“多模协同漏洞利用智能挖掘系统”，包含 2.1–2.17 共 17 项能力。它不是一道单算法题，而是一个同时涉及模型网关、Agent 编排、授权策略、网络探测、沙箱、知识库、审计、部署和权限的系统工程题。

其中存在两类目标：

1. **确定性平台能力**：模型适配、API Key、REST、任务编排、上下文、RAG、RBAC、日志、Docker 等，可以通过代码和测试明确验收。
2. **高风险研究能力**：自动 POC/EXP、真实资产探测、防护绕过、隐蔽性和“绝对防逃逸”，不能在没有授权对象和隔离环境时无边界实现，也不能承诺对任意漏洞稳定成功。

因此本实现采用一个严格、可复现的验收口径：

> 构建单租户的授权靶场平台；模型负责建议，确定性策略负责授权；只执行结构化、非破坏性的 TCP/HTTP 验证；所有目标必须被部署 allowlist 与人工批准 scope 同时覆盖；所有副作用被审计。

这样既真实完成 2.1–2.17 的平台闭环，也不会把交付物变成无边界攻击工具。

## 2. 总体算法与架构

### 2.1 四层决策模型

每个可能产生副作用的请求依次通过：

```text
身份认证 → RBAC 权限 → Scope/审批/状态策略 → 工具参数策略 → 执行
```

任何一层失败都拒绝执行，并记录拒绝审计。模型输出、RAG 文档、上下文摘要和技能 manifest 都不能跳过这四层。

### 2.2 授权范围算法

Scope 保存：

- 精确主机或明确 CIDR；
- 允许协议集合；
- 允许端口集合；
- 过期时间；
- 创建者、审批者、审批时间、理由；
- 对以上不可变字段计算的 SHA-256 `scope_hash`。

对目标 `T` 和请求端口集合 `R`，执行条件是：

```text
scope.approved
AND now < scope.expires_at（若配置）
AND host(T) matches scope.target_pattern
AND host(T) matches deployment.allowed_hosts
AND R ⊆ (scope.ports ∩ deployment.allowed_ports)
AND protocol(T) ∈ scope.protocols
AND stored_scope_hash == recomputed_scope_hash
```

网络连接前再次 DNS 解析目标。解析得到的每一个地址都必须安全；随后直接连接刚验证的 IP，不再连接 hostname，从而避免“验证时解析为允许 IP、连接时重新解析为越界 IP”的 DNS rebinding/TOCTOU。

### 2.3 任务 DAG 与状态机

任务创建时生成固定上界的 DAG：

```text
scope.check
  → asset.safe_probe
  → validation.safe_check
  → report.generate
```

任务状态：

```text
pending_approval → approved → running → succeeded
       │              │           ├→ failed
       └→ cancelled   └→ cancelled└→ cancelled
```

任务保存创建时的 `scope_hash`。审批和执行时重新计算 scope hash，只要授权内容有任何变化，旧任务就失效。审批者必须与创建者不同。

同一任务由进程内 `asyncio.Lock` 串行化；全局由 `Semaphore` 限制并发数；数据库状态更新带 `WHERE status=...` 条件，保证竞态下只有一个合法状态迁移成功。

### 2.4 安全验证计划

系统不接受任意 payload 或 shell 字符串。Planner 只能生成以下结构化步骤：

- `tcp_connect(host, port)`；
- `http_request(host, port, method=GET|HEAD, path, expected_status, body_pattern)`；
- 纯本地 assertion。

HTTP 禁止自动跟随重定向，正文最多读取 64 KiB，证据在清洗 secret 后最多保留 1,000 字符摘要。`asset_inventory` 可用端口开放作为信号；漏洞验证/回归任务必须命中显式 marker，单纯可达不会产生漏洞信号。报告固定提示该信号不等于漏洞已被证明可利用。

### 2.5 模型网关

Provider 统一抽象为：

```text
complete(messages, model, max_tokens) -> text
```

实现三类 Provider：

- `mock`：离线、确定性验收；
- `openai_compatible`：调用 `/chat/completions`；
- `ollama`：调用 `/api/chat`。

Gateway 按 `priority` 依次选择 Provider，使用每分钟滑动窗口限流；单 Provider 连续失败三次后熔断 30 秒；错误时切换下一个 Provider。系统安全提示由 Gateway 强制插入，API 请求只允许 `user/assistant` 两种消息角色，不能注入第二个 system prompt。

Provider Key 只在网关内解密。数据库保存 Fernet 密文，API 只返回 `has_api_key`，审计只保存是否配置，不保存值。

### 2.6 上下文与 RAG

上下文以 `task_id` 命名空间保存，支持：

- `private`：只有消息所有者可见；
- `task`：同任务可见；
- 常见 API Key、Bearer Token、password、secret 等写入前清洗；
- token 粗略估算；
- checkpoint 保存结构化安全信封和最近上下文摘要。

重要授权信息不依赖自然语言摘要。checkpoint 的安全信封始终从任务表重新生成，包含 scope、target、intent、approval、status 和“执行前必须重验”的固定策略。

RAG 先在 SQL 层按角色允许的 classification 过滤，再做轻量 token 相似度排序。每条结果包含 source、version、content hash、classification，并标记 `untrusted_evidence_only`，防止知识文本被误当作授权指令。

### 2.7 审计链

每条审计记录包含：

```text
timestamp, actor, action, resource_type, resource_id,
outcome, redacted_details, prev_hash, entry_hash
```

计算公式：

```text
entry_hash = HMAC-SHA256(
  audit_key,
  prev_hash || canonical_json(current_entry_without_hashes)
)
```

验证时从创世 hash `00...00` 顺序重算。修改、删除或重排任一记录都会造成链不连续。脱敏发生在 HMAC 和落库之前，且递归处理嵌套对象、消息文本、URL query、Bearer Token 和常见 secret 形式。

### 2.8 沙箱

沙箱入口不是任意命令执行。参数策略只允许：

- `python --version`；
- 有界 `python -m pytest` / `pytest`，且 flag 与路径均经过白名单校验。

三种模式：

- `dry_run`：默认，只验证参数不执行；
- `local`：仅开发，最小环境变量、独立临时目录；生产配置会拒绝；
- `docker`：`--network none --read-only --cap-drop ALL --security-opt no-new-privileges`，再限制用户、PID、CPU、内存、tmpfs、输出和时间。

生产环境要求镜像用 digest 固定。普通容器仍不被描述为绝对防逃逸；真实不可信 runner 应部署到独立 Linux VM/主机。

## 3. 模块与代码解释

| 文件 | 职责 |
|---|---|
| `solve_module2.py` | `serve/check/demo` 三个入口；demo 完成端到端验收 |
| `apps/control-plane/src/vulnlab/config.py` | 环境变量、主密钥、执行模式、allowlist 和生产安全校验 |
| `apps/control-plane/src/vulnlab/db.py` | SQLite schema、短连接、事务和索引 |
| `apps/control-plane/src/vulnlab/security.py` | API Key HMAC、RBAC、用户创建和递归脱敏 |
| `apps/control-plane/src/vulnlab/audit.py` | 审计追加、规范 JSON、HMAC 链和完整性验证 |
| `apps/control-plane/src/vulnlab/scope.py` | 目标解析、精确/CIDR 匹配、scope hash、DNS/IP 重验和探测 |
| `apps/control-plane/src/vulnlab/model_gateway.py` | Provider 密钥、统一适配、滑动限流、熔断、failover |
| `apps/control-plane/src/vulnlab/skills.py` | 内置技能、动态 manifest、任务分配和协议 schema |
| `apps/control-plane/src/vulnlab/context.py` | 消息 namespace、secret scrubber、摘要和 checkpoint |
| `apps/control-plane/src/vulnlab/rag.py` | 分类 ACL 前置过滤、版本化全文检索和 provenance |
| `apps/control-plane/src/vulnlab/orchestrator.py` | DAG 编译、职责分离审批、状态机、执行、取消和证据 |
| `apps/control-plane/src/vulnlab/sandbox.py` | 命令 schema、dry-run/local/docker runner 与配额 |
| `apps/control-plane/src/vulnlab/app.py` | 31 个 API 资源路径、认证/对象鉴权、统一异常和安全响应头 |
| `lab/` | 不含真实漏洞的 vulnerable/patched 合成标记靶场 |
| `tests/` | API、RBAC、授权、任务、密钥、审计、上下文、RAG、沙箱回归 |

## 4. 复杂度分析

设：

- `P` 为 Scope 中允许端口数；
- `A` 为一次 DNS 解析返回的地址数；
- `S` 为任务步骤数（当前上限 32，实际 1–2 个网络步骤）；
- `M` 为任务上下文消息数；
- `D` 为 RAG 文档数；
- `L` 为文档平均字符/Token 数；
- `E` 为审计事件数。

| 操作 | 时间复杂度 | 空间复杂度 | 说明 |
|---|---:|---:|---|
| Scope 静态校验 | `O(P)` | `O(P)` | 端口集合求交与包含判断 |
| DNS/IP 重验 | `O(A)` | `O(A)` | 校验所有解析结果，任一越界即拒绝 |
| DAG 生成 | `O(S)` | `O(S)` | 步骤数有硬上限 |
| 任务执行 | `O(S × (DNS + timeout))` | `O(S + evidence)` | 串行低速率，避免突发扫描 |
| checkpoint | `O(M)` | `O(min(M,12)) + state` | 读取消息，摘要只保留最近 12 条 |
| RAG 查询 | `O(D × L)` | `O(D)` | SQLite 基线；生产可替换倒排/向量索引 |
| 审计追加 | 均摊 `O(1)` | `O(1)` | 查询最后 hash 并追加 |
| 审计全链验证 | `O(E)` | `O(1)` | 顺序重算 HMAC |
| Provider 限流 | 均摊 `O(C)` | `O(C)` | `C` 为最近一分钟调用数，过期项出队 |

## 5. 数据安全与失败策略

### 5.1 默认拒绝

- 未认证：401；
- 已认证但角色不足：403，并记录 `authorization.denied`；
- 目标/端口/协议/过期/hash 不匹配：422/409；
- 未审批或非法状态：409；
- 沙箱参数不在 schema：422；
- 所有模型 Provider 失败：503，不降级为越过策略的本地执行。

### 5.2 机密处理

- 平台 API Key：HMAC-SHA256 后保存；
- Provider Key：Fernet 加密；
- Provider Key 轮换：write-only header；
- 日志/上下文/RAG：落库前模式清洗；
- `.env` 被 `.gitignore` 排除；
- 生产环境必须显式提供 admin/master key，禁止默认 key 和 local executor。

### 5.3 竞态与恢复

SQLite 事务用 `BEGIN IMMEDIATE` 和进程写锁串行化；每次连接均及时关闭，兼容 Windows 文件锁。状态迁移使用条件更新。取消运行中任务时设置 per-task event，任务每一步前检查，迟到结果只有在数据库仍为 `running` 时才能提交。

本实现是单进程参考版本；生产多 worker 版应把 lock/lease/fencing token 放入 PostgreSQL/Redis，并继续用数据库条件更新与幂等副作用保证外部可观察的至多一次效果。

## 6. 验证结果

执行命令：

```powershell
python -m compileall -q apps/control-plane/src
python solve_module2.py demo
python -m pytest -q
docker compose --profile lab config --quiet
```

已验证：

- Python 编译通过；
- 端到端 demo 成功；
- 41 项测试全部通过，包括 vulnerable/patched HTTP 对照、并发单副作用、模型输入密钥清洗、旧库迁移和对象越权回归；
- OpenAPI 3.1 正常生成；
- Docker Compose 配置校验通过；
- 审计链在正常数据下有效，篡改单条记录后可检测；
- Provider secret 在 API、DB 密文和审计中均不出现明文；
- system 消息注入、任意 shell、通配 scope、越界端口、自审批均被拒绝。

Docker Desktop Engine 已实际启动；Compose 配置校验通过，API 与 lab Dockerfile 的 `buildx --check` 均为零警告。完整构建尝试被 Docker Hub 基础层下载持续停滞阻塞，属于外部网络条件；缓存已保留，网络恢复后可直接重试 `docker compose --profile lab build`。

## 7. 与原始高风险指标的关系

“完整完成”不能解释为无条件承诺自动 0day、任意 EXP、防护绕过和隐蔽攻击。本交付完整实现的是**可以被工程验收的平台与安全闭环**：

- 2.6 以结构化、非破坏性验证和 vulnerable/patched 合成靶场实现；
- 2.7 仅在精确授权范围内实现；
- 2.10 提供可执行的基础强隔离，但明确普通容器不是绝对安全边界；
- 2.11 提供单租户并发任务隔离，不虚构尚未实现的多租户 SaaS 隔离；
- 2.14 攻击意图被替换为有限防御枚举，代理必须另有独立 scope。

这个边界保证系统能够真实运行、自动测试、可审计、可继续扩展，同时不依赖无法证明的营销式承诺。

## 8. 生产化扩展建议

若从验收版升级到多人生产平台，保持 API/领域模型不变，替换基础设施：

1. SQLite → PostgreSQL，RAG → PostgreSQL FTS/pgvector 或专用检索；
2. 单进程锁 → durable queue + lease + fencing token；
3. 本地证据 → S3/MinIO，数据库只存 hash 和引用；
4. API Key → OIDC/OAuth2，增加 tenant namespace、reviewer/auditor 独立角色；
5. Docker runner → 独立 VM/Kata/gVisor，网络由宿主防火墙强制 allowlist；
6. HMAC 链定期锚定到 WORM/object lock 或外部审计系统；
7. Provider secret → Vault/KMS envelope encryption；
8. 合成靶场 → 经法务/安全批准的版本化 CVE fixtures，并保留 patched 对照。

这些是规模和保证等级的升级，不影响当前 2.1–2.17 参考实现的可运行性。
