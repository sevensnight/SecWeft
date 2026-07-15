# Git 分支、提交与发布工作流

## 1. 当前状态与目标

截至 2026-07-15，本地仓库已在 `main` 分支初始化；P0 全量门禁通过后先创建可回滚的实施基线提交，再用独立文档提交把该 SHA 与最终验收证据绑定。实施基线 SHA 记录在 `docs/P0_ACCEPTANCE_REPORT.md`。本规范定义基线之后的唯一工作流。

初始化必须先保存工作区文件清单并确认没有把本机 secret、数据库、构建输出或用户无关文件纳入：

```powershell
git init -b main
git status --short --untracked-files=all
git check-ignore -v .env infrastructure/docker-compose/.env.platform work 2>$null
```

本次初始化前已审查完整文件清单、忽略规则和 secret 扫描结果。后续自动化不得在未确认范围时把整个工作区直接提交，也不得改写或删除用户已有文件。

## 2. 长期分支

- `main`：唯一长期分支，始终可构建、默认安全关闭、可部署到受控环境。
- 发布使用不可变 tag，不维护永久 `develop` 分支。
- 短期分支从最新 `main` 创建，经 Pull Request 合并后删除。

`main` 保护规则：禁止直接 push、禁止 force push、至少一名代码负责人审批、安全边界变更至少一名安全负责人审批、required checks 全通过、所有 review conversation 解决、分支与 main 无冲突。

## 3. 分支命名

格式：`<type>/<issue>-<short-kebab-description>`。

| type | 用途 | 示例 |
|---|---|---|
| `feat` | 新能力 | `feat/142-oidc-login` |
| `fix` | 缺陷修复 | `fix/215-sse-resume-gap` |
| `security` | 安全控制/漏洞修复 | `security/301-scope-revalidation` |
| `refactor` | 无外部行为变化重构 | `refactor/087-task-router-split` |
| `docs` | 纯文档 | `docs/044-p0-acceptance` |
| `chore` | 工具、依赖、CI | `chore/109-pnpm-upgrade` |
| `release` | 发布准备 | `release/1.2.0` |
| `hotfix` | 已发布严重问题 | `hotfix/1.2.1-auth-revocation` |

分支名不包含客户名、目标地址、漏洞细节、secret 或个人敏感信息。

## 4. 提交规范

采用 Conventional Commits：

```text
<type>(<scope>): <imperative summary>

<why and behavior, when needed>

Refs: #142
```

允许类型：`feat`、`fix`、`security`、`refactor`、`perf`、`test`、`docs`、`build`、`ci`、`chore`、`revert`。Scope 使用 `control-plane`、`web-console`、`contracts`、`policy`、`infra`、`docs` 等稳定边界。

示例：

```text
feat(contracts): add resumable task event stream
security(control-plane): fail closed when audit integrity fails
docs(testing): define P0 acceptance evidence
```

要求：

- 一个提交表达一个可解释意图，包含所需测试/契约/migration/文档。
- 不用“misc changes”“update files”等无信息标题。
- 生成文件与其源契约放在同一提交；不要单独手改生成物。
- 大规模机械格式化、文件移动和行为变化分开提交，便于审查。
- 不提交 secret、`.env`、数据库、`node_modules`、构建输出、备份、客户数据或真实攻击载荷。
- 破坏性变更正文包含 `BREAKING CHANGE:` 和迁移/弃用路径。
- 合并前允许交互式 rebase 整理个人分支；已共享分支避免未经协商改写历史。

## 5. Pull Request

PR 描述必须回答：

1. 问题和用户/系统影响是什么；
2. 选择了什么边界和方案；
3. 安全、租户、兼容、数据和部署影响是什么；
4. 实际运行了哪些命令，结果和环境是什么；
5. 如何回滚，migration 是否支持滚动版本；
6. 哪些能力明确不在本变更范围。

PR 尽量保持可在一次专注评审中理解。超过约 500 行人工逻辑或同时跨三个 bounded context 时，应按契约、基础设施、服务和 UI 拆成可独立通过的堆叠变更；生成代码、lockfile 和机械移动单独统计说明。

安全敏感 PR 不在公开描述放目标/载荷/凭据；使用受限安全流程共享必要细节，但修复代码仍需正常审查和测试。

## 6. Required checks

P0 最低检查：

```powershell
python -m compileall -q apps/control-plane/src solve_module2.py
python -m pytest -q -p no:cacheprovider
python tools/contracts/openapi_snapshot.py check --runtime
python tools/contracts/json_schema_check.py
python tools/contracts/check_migrations.py
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm generate:api
git diff --exit-code -- packages/shared-types/src/api.generated.ts
docker compose --env-file infrastructure/docker-compose/.env.platform.example -f infrastructure/docker-compose/platform.yml config --quiet
```

CI 还必须执行 secret、dependency/license、SAST、container/IaC 扫描并生成 SBOM。P1–P8 按测试策略增加多租户、Provider、持久编排、知识、Sandbox、验证、E2E、性能、故障和灾备 gates。

缓存命中可以节省时间，但检查结果必须绑定当前 commit、lockfile 和配置 hash。因环境缺失未运行的 required check 不能人工标绿。

## 7. 合并策略

- 默认使用 squash merge，使一个 PR 对应一个可回滚主线提交；需要保留有意义迁移序列时可使用 rebase merge。
- merge commit 只用于经批准的发布/长期分支整合，普通功能不用。
- PR 合并前更新到最新 main 并重新跑受影响 checks。
- 合并后删除短期分支；CI 在 main 再跑一次构建、测试和供应链证据。
- 回滚使用 `git revert` 生成可审计反向提交；禁止用 reset/force push 擦除 main 历史。

## 8. 版本与发布

发布 tag 使用 `vMAJOR.MINOR.PATCH`，例如 `v1.2.0`。预发布使用 `v1.0.0-rc.1`，不把 P0 工程版本标成企业 GA。

- MAJOR：外部 API/事件/配置的破坏性变化；
- MINOR：向后兼容能力；
- PATCH：向后兼容修复和安全修复。

发布流程：从 main 创建 `release/x.y.z` → 冻结契约和 migration → 全量验收 → 更新变更说明/兼容矩阵 → 合并 main → 创建签名 annotated tag → 构建一次并按 digest 晋级环境。禁止在不同环境从同一 tag 重新构建不同镜像。

Tag 说明包含 commit、OpenAPI/事件版本、migration、镜像 digest、SBOM/provenance、已知限制和升级/回滚链接。

## 9. Hotfix 与安全修复

严重生产问题从对应发布 tag/main 创建 `hotfix`，只包含最小修复、回归测试和必要 migration。修复先在隔离环境验证，再合并 main 和仍受支持 release。发布 patch tag，并验证撤销/轮换/审计等应急操作。

安全漏洞在受限渠道分级和协调披露；commit/branch/PR 不包含可直接武器化的复现、真实目标和 secret。兼容性不能阻止权限收紧或危险功能关闭，但必须提供稳定拒绝行为和运维通知。

## 10. ADR、生成物和大文件

- 改变服务边界、数据所有权、信任区、策略语义或核心技术选择时，先新增/替代 ADR。
- OpenAPI、事件 schema、migration、生成 SDK 和语义 snapshot 在同一 PR 评审。
- 二进制 Evidence、模型、数据集、报告和备份放受控对象存储；Git 只保存小型合成 fixture 和 hash/manifest。
- 引入 Git LFS 必须有容量、保留和访问控制决策，不能用 LFS 存 secret 或客户数据。

## 11. CODEOWNERS 与审批

P0 后续应在仓库内定义：

```text
/packages/api-contracts/      API/架构负责人
/infrastructure/migrations/   数据库/服务负责人
/docs/security/               安全负责人
/apps/api-gateway/            平台与安全负责人
/infrastructure/              平台负责人
```

Policy、RBAC、Scope、Sandbox、secret、审计和执行路径至少需要安全 owner；migration 需要领域 owner 与数据库 owner；前端权限变化同时需要 API owner。作者不能作为自己的唯一批准人。

## 12. P0–P8 演进

- P0：初始化 Git、保护 main、建立原子提交、基础 CI 和生成物漂移门禁。
- P1：加入 IAM/RBAC/Policy/Audit owners 和跨租户 required checks。
- P2–P4：契约/事件兼容检查成为必需，Provider/RAG 测试证据随版本保存。
- P5–P6：Sandbox/Validation 变更走双人安全审批和隔离环境 gate。
- P7：前端视觉、a11y、浏览器和 bundle 制品进入 PR。
- P8：签名 tag、镜像 provenance、SBOM、Helm diff、升级/回滚和最终验收均绑定 release。

只有 Git 历史、required checks 和发布制品三者可关联时，变更才具备企业可追溯性。
