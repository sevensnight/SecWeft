# 编码与工程规范

## 1. 适用范围

本规范适用于 `apps/`、`packages/`、`infrastructure/`、`tests/` 和 `tools/`。目标是让每次变更可读、可测、可回滚，并保持多租户、安全策略和执行隔离边界。

P0 已启用 TypeScript/ESLint、Turborepo、Pytest、契约检查、前端 bundle budget 和 Python 编译检查。Python 统一 formatter/linter/type checker、架构依赖测试和全仓安全扫描仍需在 P1 CI 中固化；在工具未进入依赖清单和 CI 前，不得声称这些门禁已验证。

## 2. 目录与依赖方向

```text
apps/                 可部署应用；只通过公开 package/契约复用
packages/             无部署生命周期的共享契约、类型、客户端、UI、配置、纯规则
infrastructure/       Compose、migration、监控和运维脚本
tests/                跨应用 characterization、契约和集成测试
tools/                可重复的代码生成、检查和工程工具
docs/                 架构、ADR、运行手册和验收口径
```

约束：

- `apps` 之间不得通过相对路径导入内部源文件；跨应用使用版本化 HTTP/事件契约。
- 一个领域实体只有一个写入服务；共享 package 不访问数据库、网络或进程全局状态，除非其职责就是受控 client。
- Control Plane 不导入模型供应商或容器运行时 SDK；Orchestrator 不连接目标网络；Sandbox 不访问控制面数据库。
- 前端业务模块只通过 `@vulnlab/api-client`/生成类型访问 API，不复制 DTO。
- 新共享 package 必须有明确 owner、API 边界、测试和至少两个真实消费者；不要为单次调用创建“通用”层。

## 3. 通用代码规则

- 文件和函数保持单一责任；业务路由只做解析、鉴权、调用 application service 和响应映射。
- 名称表达领域含义，避免 `data`、`manager`、`utils2` 一类无边界命名。
- 不提交固定成功的假业务端点、空实现或只有展示用途的微服务目录。
- 不用注释掩盖不正确代码；未完成工作必须进入可追踪问题并避免进入声称完成的路径。
- 时间使用带时区 UTC；ID、版本、状态和单位在类型/契约中显式表达。
- 公共 API、事件、配置和数据库 migration 都版本化；破坏性变化遵守兼容策略。
- 复杂分支优先提取纯函数；副作用、重试、超时和取消边界明确。
- 任意外部输入在边界处校验；内部层仍验证安全不变量，不能信任上游“已检查”布尔值。

## 4. Python

### 4.1 风格与类型

- Python 3.11+，启用 `from __future__ import annotations`。
- 公共函数、依赖注入边界、repository 和事件 handler 必须有完整类型。
- 使用 `dataclass`/Pydantic model 表达结构，不传递形状不明的嵌套 dict；兼容 adapter 可暂时保留，但要在迁移说明中标识。
- 使用 `pathlib.Path` 处理路径；不拼接未验证的用户路径。
- 异步函数只用于真实异步 I/O；不要在 event loop 中运行阻塞网络/CPU 工作。
- 资源使用 context manager，超时和取消异常不被吞掉。

### 4.2 FastAPI

- Router 按领域拆分；应用 factory 只负责依赖组合、中间件和 router 注册。
- Request/Response 都由严格 schema 描述，`extra="forbid"`；长度、集合大小和枚举设上限。
- 认证、permission、tenant/project scope 使用统一 dependency/PEP，不在 handler 内复制判断。
- 领域异常映射为稳定错误代码；不能把 traceback、SQL、secret 或内部路径返回客户端。
- `GET` 不产生业务副作用；写命令使用幂等键、expected version 和事务 Outbox。

### 4.3 当前检查

```powershell
python -m compileall -q apps/control-plane/src solve_module2.py
python -m pytest -q -p no:cacheprovider
```

P1 将 formatter、lint、import order 和静态类型检查加入 `requirements-dev.txt`、Taskfile 和 CI；规则一次性基线化，不在业务 PR 中夹带全仓无关格式改写。

## 5. TypeScript 与 React

- TypeScript strict 模式；业务代码不使用隐式 `any`，外部 `unknown` 经 schema/type guard 收窄。
- React 使用函数组件和 hooks；副作用只放在明确的 effect/query 层，依赖数组正确。
- Server state 由 TanStack Query 管理，UI/session state 由局部 state 或 Zustand 管理；不要把同一远端数据复制到两个 store。
- API Key/token 只存在内存，不进入 localStorage、sessionStorage、URL 或错误遥测。
- 路由页面使用 lazy import；ECharts、Monaco 和大型表格只在需要时加载。
- 大列表使用虚拟化；高频日志过滤/解析使用 Web Worker，主线程不做无界 JSON 处理。
- Error、loading、empty、permission denied 和 reconnect 都是组件的一等状态。
- 权限裁剪通过共享 capability model；后端仍是最终 PEP。
- 组件具备键盘和语义可访问性；颜色不是唯一状态表达。

当前检查：

```powershell
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

构建必须通过 `apps/web-console/tools/check-bundle.mjs` 预算；增大预算必须附 bundle 分析、用户影响和评审决定。

## 6. SQL 与 migration

- PostgreSQL schema 按服务所有权划分；服务账号没有其他 schema 的表权限。
- 多租户业务表显式含 `tenant_id`，项目资源同时含 `project_id`；复合唯一键/外键不能只靠全局 ID 隐式隔离。
- 可变聚合含 `created_at`、`updated_at`、`version`；审计、审批决定、执行尝试和证据使用追加语义。
- migration 成对命名 `<sequence>_<description>.up.sql/.down.sql`，包含事务、合理的 lock/statement timeout、约束和索引。
- 使用 expand/migrate/contract 支持滚动部署；大表索引、回填和约束验证不能在一个长锁事务中盲目完成。
- 参数化查询，禁止拼接字段/排序/过滤 SQL；动态标识符来自硬编码白名单。
- 状态和 JSON payload 有 CHECK；hash、时间、版本和幂等唯一性由数据库约束保护。

当前检查：

```powershell
python tools/contracts/check_migrations.py
python -m pytest tests/contract/test_postgres_migrations.py -q -p no:cacheprovider
```

静态通过不替代真实 PostgreSQL 的 up/down、已有数据、权限和并发测试。

## 7. Shell、PowerShell、YAML 与容器

- PowerShell 使用 `Set-StrictMode -Version Latest` 和 `$ErrorActionPreference='Stop'`；文件操作使用 `-LiteralPath` 并验证解析后的目标。
- POSIX shell 使用 `set -eu`；所有变量引用加引号，临时文件和退出清理明确。
- 维护脚本拒绝占位 secret、危险空路径和隐式数据删除；恢复需要显式确认。
- Compose/Kubernetes 使用 health/readiness、资源限额、非 root、只读文件系统、drop capabilities、内部网络/NetworkPolicy。
- 镜像最终使用 digest、SBOM、签名和最小 runtime；不挂 Docker Socket，不把 secret 放 build args/layer。
- YAML 重复片段可用 anchor/template，但关键安全值在最终渲染 manifest 中必须可审查。

## 8. 错误、日志和可观测性

- 错误按 `validation/auth/permission/conflict/rate/dependency/internal` 分类，稳定 `code` 与人类可读 detail 分离。
- 仅对幂等操作自动重试；指数退避、抖动、上限和总体 deadline 明确。
- 不使用裸 `except` 静默吞错；补偿失败和 DLQ 必须可观测并可人工处置。
- 结构化日志字段包含 service、environment、level、event、request/trace、tenant/project（安全 ID）、resource 和 duration。
- 使用字段白名单和递归 redaction；认证头、密码、API key、grant、模型 secret、原始证据不记录。
- 指标 label 不放 user/task/URL 等高基数字段；业务 ID 放 trace/log。

## 9. 安全编码不变量

1. 模型、RAG、Agent memory 和客户端输入从不产生授权。
2. tenant/project scope、RBAC、Policy 和资源状态在最终执行点复验。
3. Tool/Sandbox 只接受注册版本和类型化 argv，不接受 Shell 文本。
4. URL、DNS、代理、重定向和实际连接 IP 全链路 Scope 重验。
5. 高风险写入与审计 Outbox 原子；审计不可用时失败关闭。
6. 幂等、租约、fencing 和 optimistic version 由持久存储保证，不依赖单进程锁。
7. Secret 使用 reference/write-only；密文、hash 和脱敏值各自用途明确。
8. 任何跨边界数据包含 provenance、classification 和版本/digest。

## 10. 测试与评审要求

每个修复至少有能在修复前失败、修复后通过的回归测试。每个新接口至少覆盖成功、未认证、无权限/无数据范围、非法输入、冲突和依赖失败。安全核心还覆盖重复、乱序、撤销、过期、竞态和 fail-closed。

评审核对：

- 变更属于正确 bounded context，未产生跨库/跨 app 内部导入；
- 契约和生成物先行且兼容性已分类；
- tenant/project、permission、Policy、audit 没有遗漏；
- secret、日志、错误和事件经过清洗；
- 幂等、事务、版本、超时、重试、取消和资源清理明确；
- 测试真实验证失败分支，未依赖外网/真实目标；
- 部署、migration、配置和回滚影响已写入运行手册。

## 11. 完成定义

代码完成需要：实现与契约一致；相关 lint/typecheck/test/build/contract 通过；迁移可验证；文档和示例同步；没有伪造成功或未说明跳过；兼容、安全、可观测和回滚经过评审。若依赖环境缺失，状态只能是 `Blocked`，不能改写为通过。
