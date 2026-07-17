# 模块二 P5：策略决策与执行边界实现说明

## 目标

P5 的目标是在 P1-P4 的身份、编排、知识服务基础上增加中心化策略决策和执行入口 PEP，确保任何执行类兼容 API 都先经过可审计的策略判断。

## 已完成能力

- 新增 `PolicyService`，输出 `allow`、`deny`、`requires_approval` 三类决策。
- 新增 `policy_decisions` 持久表，记录 actor、action、resource、decision、reason、details、policy hash。
- 新增 `/api/v1/policies/evaluate`。
- `/api/v1/assets/probe` 和 `/api/v1/sandbox/runs` 接入 PEP。
- legacy execution disabled 时仍保持原 503 行为，同时落 policy decision。
- 策略拒绝破坏性动作、legacy disabled 执行动作、未审批任务执行、scope 失效和 sandbox shell 元字符。
- OpenAPI 升级到 `1.5.0-p5`，生成 TypeScript DTO。

## 安全边界

- P5 不开启真实扫描、漏洞利用或沙箱执行。
- Policy decision 只表达授权判断，不授予工具能力。
- 执行能力仍受当前 task approval、scope hash、审计链和 legacy 开关约束。

## 验收方式

```powershell
.\.venv\Scripts\python.exe solve_p5_baseline.py
.\.venv\Scripts\python.exe solve_p5_baseline.py --full
```
