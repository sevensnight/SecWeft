# 本地开发指南

## 1. P0 开发形态

仓库同时保留两种运行形态：

- **快速开发形态**：本机运行 FastAPI 兼容控制面和 Vite Web Console，适合单元、契约和 UI 开发。
- **平台 Compose 形态**：通过 `infrastructure/docker-compose/platform.yml` 启动 Gateway、Web、API 及 PostgreSQL、Redis、NATS JetStream、MinIO、OpenTelemetry Collector、Prometheus，适合基础设施和集成检查。

根目录 `docker-compose.yml` 是旧授权靶场原型，不是企业平台 Compose。P0 日常开发不启动其中的 `lab` profile，也不启用旧执行能力。

## 2. 前置条件

| 工具 | 基线 | 用途 |
|---|---|---|
| Python | 3.11 以上 | FastAPI、契约工具、测试 |
| Node.js | 22.17 以上 | Web Console 和 workspace 工具 |
| pnpm | 10.30 以上 | Monorepo 包管理 |
| Git | 当前受支持版本 | 生成物漂移、分支和提交审计 |
| Docker Engine/Desktop | 支持 Compose v2 | 平台依赖和镜像构建 |
| Task | 可选 | 使用 `Taskfile.yml` 的统一命令 |

Windows 使用 PowerShell 7 或 Windows PowerShell 5.1；Linux/macOS 使用 POSIX shell。Docker Desktop 必须处于运行状态，且本地端口 `8080`、`9001`、`9090` 未被占用。

## 3. 首次安装

### Windows PowerShell

```powershell
Set-Location 'D:\多模协同漏洞利用智能挖掘系统'
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
& .\.venv\Scripts\python.exe -m pip install --no-deps --editable .
corepack enable
pnpm install --frozen-lockfile
pnpm generate:api
```

若 `corepack enable` 因系统目录权限失败，可在已安装的 pnpm 10.30+ 环境直接执行 `pnpm install --frozen-lockfile`，不要使用 npm 改写 `pnpm-lock.yaml`。

### Linux/macOS

```bash
cd /path/to/多模协同漏洞利用智能挖掘系统
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
.venv/bin/python -m pip install --no-deps --editable .
corepack enable
pnpm install --frozen-lockfile
pnpm generate:api
```

依赖升级必须显式修改清单和 lockfile，并经过安全扫描与完整测试；普通安装不使用无锁版本。

## 4. 快速开发运行

为本机 API 准备仅用于开发的环境变量。Key 必须随机生成，不能复制示例占位值：

```powershell
$env:VULNLAB_ENV = 'development'
$env:VULNLAB_ADMIN_KEY = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))")
$env:VULNLAB_MASTER_KEY = (& .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
$env:VULNLAB_DB_PATH = (Join-Path $PWD 'work\dev\vulnlab.db')
$env:VULNLAB_WORKSPACE_ROOT = (Join-Path $PWD 'work\dev\workspaces')
$env:VULNLAB_EXECUTION_MODE = 'dry_run'
$env:VULNLAB_LEGACY_EXECUTION_ENABLED = 'false'
New-Item -ItemType Directory -Force -Path 'work\dev' | Out-Null
& .\.venv\Scripts\python.exe -m vulnlab.main --host 127.0.0.1 --port 8000 --reload
```

另开终端启动前端：

```powershell
Set-Location 'D:\多模协同漏洞利用智能挖掘系统'
$env:VITE_API_PROXY_TARGET = 'http://127.0.0.1:8000'
pnpm --filter @vulnlab/web-console dev
```

访问 `http://127.0.0.1:5173`。API 健康端点是 `http://127.0.0.1:8000/health`。P0 Web Console 的 API Key 只保存在内存会话中；刷新后重新输入是预期安全行为。

不得把 `VULNLAB_LEGACY_EXECUTION_ENABLED` 改成 `true` 作为普通开发捷径。旧执行只用于隔离合成靶场的 characterization test，不能访问互联网或未授权地址。

## 5. 平台 Compose 启动

先复制环境模板并替换所有 `GENERATE_` 值：

```powershell
Copy-Item infrastructure/docker-compose/.env.platform.example infrastructure/docker-compose/.env.platform
& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
& .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

第一条生成普通随机 secret，可为每个数据库、Redis、NATS、MinIO 和管理员密码分别运行；第二条只生成 Fernet master key。不要把 `.env.platform` 提交到 Git。

在启动前执行静态配置检查：

```powershell
docker compose --env-file infrastructure/docker-compose/.env.platform -f infrastructure/docker-compose/platform.yml config --quiet
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure/scripts/start.ps1
```

有 Task CLI 时等价命令为 `task platform:config` 和 `task platform:up`。启动脚本会拒绝占位值、过短 secret、非法 Fernet key，并使用 `docker compose up --detach --wait --build` 等待健康状态。

平台入口：

| 地址 | 作用 | 暴露范围 |
|---|---|---|
| `http://127.0.0.1:8080` | Caddy Gateway + Web Console + `/api` | 默认仅回环 |
| `http://127.0.0.1:9001` | MinIO 管理台 | 默认仅回环 |
| `http://127.0.0.1:9090` | Prometheus | 默认仅回环 |
| `http://127.0.0.1:8081` | 可选开发 Keycloak（`-Identity`） | 默认关闭、仅回环 |

PostgreSQL、Redis、NATS、MinIO API 和 OTel Collector 只在内部 `backend` 网络可见。P0 Compose 提供默认关闭的 Keycloak `identity` profile，用于验证 Authorization Code + PKCE 的开发集成前置条件；兼容控制面尚未消费 OIDC token，真正的身份、租户上下文与八角色授权仍属于 P1，不能把 IdP 容器健康误报为 P1 登录完成。

可选 IdP 启动命令：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure/scripts/start.ps1 -Identity
```

若本机 `8080` 已由其他项目使用，可仅在当前终端覆盖 `PLATFORM_GATEWAY_PORT`（例如 `18080`）后启动；不要停止或改写无关服务。

## 6. 日常检查

快速回归：

```powershell
& .\.venv\Scripts\python.exe -m compileall -q apps/control-plane/src solve_module2.py
& .\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

契约和迁移：

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/contract -q -p no:cacheprovider
pnpm --filter @vulnlab/api-contracts test
pnpm generate:api
git diff --exit-code -- packages/shared-types/src/api.generated.ts
```

完整 P0 聚合命令：

```powershell
task check
```

未安装 Task 时依次运行 `Taskfile.yml` 的子命令。任何因 Docker、浏览器或 Linux 隔离环境缺失而未执行的检查，都必须标为 `Blocked`，不能写成通过。

## 7. 停止、日志和清理

```powershell
docker compose --env-file infrastructure/docker-compose/.env.platform -f infrastructure/docker-compose/platform.yml ps
docker compose --env-file infrastructure/docker-compose/.env.platform -f infrastructure/docker-compose/platform.yml logs --follow --tail=200
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure/scripts/stop.ps1
```

停止脚本不删除 named volumes。`docker compose down -v` 会删除平台数据，不属于普通开发清理命令；只有确认环境可丢弃并已有所需备份时才能使用。

Python 临时数据库、workspace 和覆盖率输出位于 Git 忽略目录。不要用递归清理命令作用于工作区根目录。

## 8. 常见故障定位

| 现象 | 检查 | 处理 |
|---|---|---|
| `Docker Engine is unavailable` | `docker version` | 启动 Docker Desktop/daemon 后重试 |
| Compose 拒绝 secret | 检查 `.env.platform` 是否仍有 `GENERATE_`，长度是否至少 24 | 为每项生成独立随机值 |
| Fernet key 无效 | 检查是否为 URL-safe 32-byte key | 用文档命令重新生成 |
| 前端请求 401 | API Key 是否在当前内存会话中 | 重新输入本次开发 Key，不写入 localStorage |
| 生成类型漂移 | `pnpm generate:api` 后查看 diff | 契约和生成物一同评审提交 |
| SSE 无更新 | 检查 Task 所有权、`Last-Event-ID`、代理缓冲和 API 日志 | 先调用持久事件列表核对缺口 |
| Compose 服务 unhealthy | `docker compose ... ps` 和对应服务日志 | 先解决最早失败的依赖，不反复重建全部卷 |

## 9. 本地开发安全边界

- 仅使用合成数据、Mock Provider 和回环地址。
- 真实供应商 Key、客户资产、真实漏洞载荷和生产备份不得进入开发环境。
- API、Gateway、浏览器和容器日志必须经过 secret 清洗。
- Windows 本地容器不能代表 seccomp、MAC 或 gVisor 验收；Sandbox 隔离测试必须在 P5 的专用 Linux 环境执行。
- P0 不执行漏洞验证；开发服务器成功启动只证明工程基线可运行。
