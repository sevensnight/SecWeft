# 模块二 P4：知识上下文、证据与 RAG 服务实现说明

## 目标

P4 的目标是把 P3 编排中的“知识检索/证据/上下文”占位升级为可持久化、可审计、可恢复、可被契约约束的企业级知识服务，同时继续保持安全默认值：恢复上下文不恢复执行权限，RAG 命中只能作为不可信证据输入，不能授予工具或越过审批。

## 已完成能力

- 任务上下文消息增加 `sequence_no` 与 `content_hash`，写入前执行密钥脱敏。
- 检查点增加 `summary_hash`、`state_hash`、`restore_policy_hash` 和 `evidence_count`。
- 新增任务证据账本 `evidence_items`，保存标题、来源、分类、信任级别、内容哈希和元数据。
- RAG 文档写入时生成确定性 chunk，新增 `rag_chunks` 表和 chunk 级检索结果。
- RAG 检索在 SQL 层先按分类 ACL 预过滤，再对 chunk 打分。
- 检索结果返回 `citation`，包含 document/chunk/source/version/content hash/chunk hash。
- 新增知识包接口，把任务上下文、最新检查点、证据和 RAG citation 组合成只读输入。
- OpenAPI 升级到 `1.4.0-p4`，签入语义快照并重新生成 TypeScript DTO。

## 安全边界

- `context/restore` 只返回摘要和当前安全信封，不恢复任何历史授权。
- `knowledge-pack` 明确返回 `execution_authorized=false`。
- RAG 结果标记为 `untrusted_evidence_only`。
- 证据和 RAG 文档按角色分类上限写入；越权分类写入返回 403。
- P4 未开放真实漏洞利用、真实扫描、沙箱执行或公共互联网探测。

## 验收方式

```powershell
.\.venv\Scripts\python.exe solve_p4_baseline.py
.\.venv\Scripts\python.exe solve_p4_baseline.py --full
```

专项测试覆盖：

- 检查点哈希和证据快照；
- RAG chunk citation；
- RAG 分类 ACL 预过滤；
- 证据分类写入限制；
- 知识包只读安全信封；
- OpenAPI P4 契约与运行时投影一致。
