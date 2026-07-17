# API 调用示例

## P1 企业接口

先通过组织 OIDC 的 Authorization Code + PKCE 登录。下面只从当前进程环境读取短期 access token，不把 token 写入 URL、脚本或持久存储：

```powershell
$base = 'http://127.0.0.1:8000/api/v1'
$token = $env:VULNLAB_TEST_ACCESS_TOKEN
$headers = @{
  Authorization = "Bearer $token"
  'X-Request-ID' = [guid]::NewGuid().ToString()
}
$session = Invoke-RestMethod -Uri "$base/session" -Headers $headers
$session
```

创建 Organization 和 Project 的写请求必须使用独立幂等键：

```powershell
$organizationHeaders = $headers.Clone()
$organizationHeaders['Idempotency-Key'] = "organization-$([guid]::NewGuid())"
$organizationBody = @{ slug = 'security-research'; display_name = 'Security Research' } | ConvertTo-Json
$organization = Invoke-RestMethod -Method Post -Uri "$base/organizations" -Headers $organizationHeaders -ContentType 'application/json' -Body $organizationBody

$projectHeaders = $headers.Clone()
$projectHeaders['Idempotency-Key'] = "project-$([guid]::NewGuid())"
$projectBody = @{
  organization_id = $organization.id
  slug = 'synthetic-lab'
  display_name = 'Synthetic Lab'
} | ConvertTo-Json
$project = Invoke-RestMethod -Method Post -Uri "$base/projects" -Headers $projectHeaders -ContentType 'application/json' -Body $projectBody
```

选择项目范围后读取有效配置和审计：

```powershell
$projectHeaders = $headers.Clone()
$projectHeaders['X-Project-ID'] = $project.id
Invoke-RestMethod -Uri "$base/config/effective?project_id=$($project.id)" -Headers $projectHeaders
Invoke-RestMethod -Uri "$base/audit/events?project_id=$($project.id)" -Headers $projectHeaders
```

权限来自 `/session`，但客户端裁剪不是授权证据；后端仍会对每个调用重新解析角色并执行 RLS。

## Legacy 兼容接口

以下 PowerShell 示例展示正常职责分离流程。服务已在 `127.0.0.1:8000` 启动，管理员 Key 来自 `VULNLAB_ADMIN_KEY`。

## 1. 管理员创建 analyst

```powershell
$base = "http://127.0.0.1:8000/api/v1"
$admin = @{ "X-API-Key" = $env:VULNLAB_ADMIN_KEY }
$user = Invoke-RestMethod -Method Post -Uri "$base/users" -Headers $admin -ContentType "application/json" -Body (@{
  username = "lab-analyst"
  role = "analyst"
} | ConvertTo-Json)
$analyst = @{ "X-API-Key" = $user.api_key }
```

用户 Key 只返回一次。

## 2. analyst 创建授权范围

```powershell
$scope = Invoke-RestMethod -Method Post -Uri "$base/scopes" -Headers $analyst -ContentType "application/json" -Body (@{
  name = "synthetic-vulnerable-lab"
  target_pattern = "target-vulnerable"
  protocols = @("http", "tcp")
  ports = @(8080)
} | ConvertTo-Json)
```

如果 API 不在 Compose 内、靶场映射到本机，应将 target 配成已列入 `VULNLAB_ALLOWED_HOSTS` 的精确主机，并将端口同时加入 `VULNLAB_ALLOWED_PORTS`。

## 3. 管理员独立审批范围

```powershell
$scope = Invoke-RestMethod -Method Post -Uri "$base/scopes/$($scope.id)/approve" -Headers $admin -ContentType "application/json" -Body (@{
  approved = $true
  reason = "dedicated synthetic lab approved for marker regression"
} | ConvertTo-Json)
```

## 4. analyst 创建任务

```powershell
$task = Invoke-RestMethod -Method Post -Uri "$base/tasks" -Headers $analyst -ContentType "application/json" -Body (@{
  title = "Synthetic finding regression"
  target = "http://target-vulnerable:8080"
  intent = "defensive_regression"
  indicators = @("VULNLAB_SYNTHETIC_FINDING")
  scope_id = $scope.id
} | ConvertTo-Json)
$task.plan | ConvertTo-Json -Depth 8
```

## 5. 管理员审批并异步派发

```powershell
$task = Invoke-RestMethod -Method Post -Uri "$base/tasks/$($task.id)/approve" -Headers $admin -ContentType "application/json" -Body (@{
  approved = $true
  reason = "GET-only non-destructive plan reviewed"
} | ConvertTo-Json)

$dispatchHeaders = $admin.Clone()
$dispatchHeaders["Idempotency-Key"] = [guid]::NewGuid().ToString()
$task = Invoke-RestMethod -Method Post -Uri "$base/tasks/$($task.id)/executions" -Headers $dispatchHeaders

Invoke-RestMethod -Uri "$base/tasks/$($task.id)/stages" -Headers $admin
Invoke-RestMethod -Uri "$base/tasks/$($task.id)/executions" -Headers $admin
```

P3 企业契约不发布同步 `/run`；长任务通过 durable queue 派发，再用查询或 SSE 观察状态。开发兼容层仍可在本地测试中调用 `/run` 驱动一个内置 worker。

实时事件：

```powershell
Invoke-WebRequest -Uri "$base/tasks/$($task.id)/events/stream" -Headers $admin
```

暂停、恢复和失败重试：

```powershell
Invoke-RestMethod -Method Post -Uri "$base/tasks/$($task.id)/pause" -Headers $admin -ContentType "application/json" -Body (@{ reason = "operator hold" } | ConvertTo-Json)
Invoke-RestMethod -Method Post -Uri "$base/tasks/$($task.id)/resume" -Headers $admin -ContentType "application/json" -Body (@{ reason = "resume approved" } | ConvertTo-Json)
Invoke-RestMethod -Method Post -Uri "$base/tasks/$($task.id)/retry" -Headers $admin -ContentType "application/json" -Body (@{ reason = "transient worker failure recovered" } | ConvertTo-Json)
```

对 `target-patched` 重复创建一个 scope/task，指标应不命中。系统仍会把执行标记为 `succeeded`，因为这表示验证流程正常完成；漏洞信号看 `result.validation_signal` 和每步证据。

## 6. Agent、Workflow 和 Skill 注册表

```powershell
Invoke-RestMethod -Uri "$base/agents" -Headers $admin
Invoke-RestMethod -Uri "$base/workflows" -Headers $admin
Invoke-RestMethod -Uri "$base/skills" -Headers $admin
Invoke-RestMethod -Uri "$base/protocols/tools" -Headers $admin
Invoke-RestMethod -Uri "$base/task-dead-letters?limit=20" -Headers $admin
```

这些接口只注册声明式定义，不上传可执行代码；工具权限、资源限制、超时、审批要求和调用统计都会进入响应和审计。

## 7. 模型网关

默认离线 mock 可直接验证。响应包含 usage、cost、failover_count 和 tool_protocol；不会回显任何 Provider secret：

```powershell
Invoke-RestMethod -Method Post -Uri "$base/models/complete" -Headers $analyst -ContentType "application/json" -Body (@{
  purpose = "reporting"
  max_tokens = 256
  response_format = @{ type = "json_object" }
  tools = @(@{
    name = "scope.check"
    description = "Check whether a target is inside the approved scope."
    input_schema = @{ type = "object"; properties = @{ target = @{ type = "string" } } }
  })
  messages = @(@{ role = "user"; content = "Summarize this authorized regression result." })
} | ConvertTo-Json -Depth 5)
```

查看 provider health、模型目录和调用账本：

```powershell
Invoke-RestMethod -Uri "$base/providers/health" -Headers $admin
Invoke-RestMethod -Uri "$base/models/catalog" -Headers $admin
Invoke-RestMethod -Uri "$base/models/invocations?limit=20" -Headers $admin
```

SSE 流式输出：

```powershell
Invoke-WebRequest -Method Post -Uri "$base/models/stream" -Headers $analyst -ContentType "application/json" -Body (@{
  stream = $true
  messages = @(@{ role = "user"; content = "Stream a short authorized summary." })
} | ConvertTo-Json -Depth 5)
```

注册外部 Provider 仅限管理员；`api_key` 会在写入前加密且不会在响应中返回。轮换也可以通过 `PUT /providers/{id}/secret` 的 `X-Provider-API-Key` 请求头完成。调用账本只保存 hash、usage、cost、状态和延迟，不保存 prompt/response 正文。

## 8. RAG 与 checkpoint

```powershell
Invoke-RestMethod -Method Post -Uri "$base/rag/documents" -Headers $analyst -ContentType "application/json" -Body (@{
  title = "Patch regression runbook"
  content = "Use explicit non-destructive markers and compare vulnerable/patched fixtures."
  source = "internal://runbooks/patch-regression"
  classification = "internal"
  version = "1"
  tags = @("patch", "regression")
} | ConvertTo-Json)

Invoke-RestMethod -Method Post -Uri "$base/rag/search" -Headers $analyst -ContentType "application/json" -Body (@{
  query = "patch regression marker"
  top_k = 5
} | ConvertTo-Json)

Invoke-RestMethod -Method Post -Uri "$base/tasks/$($task.id)/checkpoints" -Headers $analyst
```

## 9. 审计校验

```powershell
Invoke-RestMethod -Uri "$base/audit/verify" -Headers $admin
Invoke-RestMethod -Uri "$base/audit?limit=100" -Headers $admin
```

`valid=false` 表示审计库发生删除、篡改、重排或使用了错误的 master key，应立即停止高风险执行并调查。
