# Control Plane（P0 兼容运行时）

该目录承载现有 FastAPI 单节点参考实现，并在 P0 完成路由、依赖、运行时中间件和服务装配的模块化拆分。它用于保留行为回归证据，不代表目标企业控制面已经完成。

当前不变量：

- `VULNLAB_LEGACY_EXECUTION_ENABLED=false` 为默认值；任务执行、资产探测和沙箱运行返回 `503`。
- P0 只对健康、系统能力、任务投影和任务事件建立 API-first 兼容契约。
- SQLite、API Key、四角色和进程内并发均为 legacy 限制；Tenant/Project/OIDC/八角色/PostgreSQL 状态真相在 P1/P3 迁移。
- 保留 scope 规范化、递归脱敏、审计 HMAC 链、凭据不回显、RAG ACL 前置过滤等安全算法及 characterization tests。

开发入口：

```powershell
python -m pytest -q
python solve_module2.py serve --host 127.0.0.1 --port 8000
```

真实执行能力只允许在专用合成靶场测试中显式开启，不得用于公网或未授权目标。
