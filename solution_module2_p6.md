# 模块二 P6：受控验证计划账本与审批说明

## 目标

P6 在 P5 的策略决策边界之上增加“受控验证计划”能力：分析员可以为任务创建非破坏性的验证计划草稿，提交给管理员审批；管理员可以批准或拒绝计划。审批只改变计划状态，不触发扫描、漏洞利用、沙箱运行或任何真实执行。

## 已完成能力

- 新增 `validation_plans` 持久化表，保存计划内容、计划哈希、关联策略决策、创建人、提交时间、审核人、审核时间和审核理由。
- 新增 `ValidationPlanService`，提供 `create/list/get/submit/review` 生命周期能力。
- 创建计划时逐条调用 `PolicyService.evaluate` 做预检；目标 host/port 不在 scope 内会直接拒绝创建。
- 计划内容使用规范化 JSON 计算 SHA-256 哈希，便于审计和审批前后比对。
- 状态机限制为 `draft -> submitted -> approved/rejected`，非对应状态操作返回冲突。
- 管理员才可审核；分析员/操作员可创建和提交。
- 新增 API：
  - `POST /api/v1/tasks/{task_id}/validation-plans`
  - `GET /api/v1/tasks/{task_id}/validation-plans`
  - `GET /api/v1/validation-plans/{plan_id}`
  - `POST /api/v1/validation-plans/{plan_id}/submit`
  - `POST /api/v1/validation-plans/{plan_id}/review`
- OpenAPI 升级到 `1.6.0-p6`，同步生成 TypeScript DTO。

## 安全边界

- P6 不新增执行端点；没有 `/validation-runs` 或 `/validation-executions`。
- 计划审批不调用 task execution、sandbox、asset probe 或外部网络客户端。
- `destructive` 固定为 `false`，计划仅描述非破坏性验证步骤。
- 每个计划步骤都先经过当前 scope 和策略预检，策略拒绝即无法入库。
- 已批准计划仍只是审计账本状态，不代表授予运行能力。

## 验收方式

```powershell
.\.venv\Scripts\python.exe solve_p6_baseline.py
.\.venv\Scripts\python.exe solve_p6_baseline.py --full
```

核心测试：

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_p6_validation_plans.py tests\contract\test_openapi_contract.py -q
```
