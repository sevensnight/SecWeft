# API 调用示例

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

## 5. 管理员审批并执行

```powershell
$task = Invoke-RestMethod -Method Post -Uri "$base/tasks/$($task.id)/approve" -Headers $admin -ContentType "application/json" -Body (@{
  approved = $true
  reason = "GET-only non-destructive plan reviewed"
} | ConvertTo-Json)

$result = Invoke-RestMethod -Method Post -Uri "$base/tasks/$($task.id)/run" -Headers $admin
$result.result | ConvertTo-Json -Depth 10
```

对 `target-patched` 重复创建一个 scope/task，指标应不命中。系统仍会把执行标记为 `succeeded`，因为这表示验证流程正常完成；漏洞信号看 `result.validation_signal` 和每步证据。

## 6. 模型网关

默认离线 mock 可直接验证：

```powershell
Invoke-RestMethod -Method Post -Uri "$base/models/complete" -Headers $analyst -ContentType "application/json" -Body (@{
  purpose = "reporting"
  max_tokens = 256
  messages = @(@{ role = "user"; content = "Summarize this authorized regression result." })
} | ConvertTo-Json -Depth 5)
```

注册外部 Provider 仅限管理员；`api_key` 会在写入前加密且不会在响应中返回。轮换也可以通过 `PUT /providers/{id}/secret` 的 `X-Provider-API-Key` 请求头完成。

## 7. RAG 与 checkpoint

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

## 8. 审计校验

```powershell
Invoke-RestMethod -Uri "$base/audit/verify" -Headers $admin
Invoke-RestMethod -Uri "$base/audit?limit=100" -Headers $admin
```

`valid=false` 表示审计库发生删除、篡改、重排或使用了错误的 master key，应立即停止高风险执行并调查。
