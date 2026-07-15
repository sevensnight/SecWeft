# ADR-0004：Sandbox 作为独立 Linux 隔离执行平面

- 状态：Accepted
- 日期：2026-07-10
- 决策范围：命令、工具和受控验证的执行边界

## 背景

模型生成内容、第三方工具和验证载荷均不可信。普通 API 容器、开发主机和 Docker Socket 不能成为执行边界。Windows 开发环境无法代表 Linux seccomp/MAC/gVisor 的实际隔离效果。

## 决策

1. Sandbox worker 部署在独立 Linux VM/节点，与 API/control plane 分离。
2. 生产优先使用 Kubernetes/containerd + gVisor；需要更强隔离时评估 Firecracker。
3. API 容器不挂 Docker Socket，不运行模型生成命令或代码。
4. Sandbox 只接受注册的 Tool/Skill 版本、类型化 argv 和有效 ExecutionGrant。
5. 默认无外部网络；仅按 Scope 创建精确 egress allowlist。
6. 非 root、只读根文件系统、临时工作目录、drop all capabilities、no-new-privileges、seccomp、AppArmor/SELinux、CPU/内存/PID/磁盘/时间配额。
7. 每任务独立实例；完成、取消、超时和 worker 异常都触发回收。
8. 结果以 hash/URI/资源用量返回；Sandbox 不自行宣布漏洞成立。

## 备选方案

### 在 API 进程中运行 subprocess

拒绝。直接暴露宿主机环境、凭据和文件系统。

### API 容器挂 Docker Socket 创建子容器

拒绝。Docker Socket 等价于高权限宿主控制面。

### 普通 Docker 容器即“绝对防逃逸”

拒绝。容器共享内核，不应承诺绝对隔离。

### 所有验证使用独立物理机

暂不采用为唯一方案。隔离强但成本和调度效率不足；保留给最高敏感环境。

## 结果

正面结果：将不可信执行从业务服务隔离；网络和资源可强制；便于独立扩缩容和回收。

负面结果：需要 Linux 专用基础设施、镜像供应链、节点加固和较高运维成本；本地 Windows 不能完整验证。

## 约束

- P0 不启用漏洞验证；仅允许固定健康命令和无网络 smoke。
- P5 通过隔离验收前，P6 不得开始。
- 镜像使用 digest 固定、签名验证、SBOM 和漏洞扫描。
- Secret 按最小范围短期注入，不能写入镜像或持久快照。
- 任何网络重定向、代理和 DNS 解析都需要 Scope 重验。

## 验证

- 测试特权、HostNetwork、HostPID、敏感挂载、Docker Socket 和外网访问全部拒绝。
- CPU/内存/PID/磁盘/超时限制实际生效。
- 进程崩溃、节点丢失和取消后资源最终回收。
- 旧 fencing token 无法提交结果。
- Linux CI/测试集群运行 seccomp/MAC/gVisor 集成测试；Windows 仅运行契约测试。
