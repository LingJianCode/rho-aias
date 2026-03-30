# rho-aias

**rho-aias** 是一个基于 eBPF 和 XDP（eXpress Data Path）技术的高性能网络防火墙系统，在网络驱动层（L3）拦截和过滤数据包，相比传统的 netfilter/iptables 具有更优的性能。

## 功能特性

### 核心功能

- **eBPF XDP 包过滤**：在驱动层实现高性能数据包拦截
- **多源规则管理**：支持手动规则、威胁情报、地域封禁、WAF 自动封禁等多种规则来源
- **位掩码追踪**：通过位掩码标记规则来源，避免多源冲突
- **RESTful API**：提供完整的 HTTP API 进行规则管理
- **持久化存储**：规则自动持久化到本地，支持离线启动
- **Cron 定时任务**：支持独立的定时更新调度
- **认证与授权**：JWT 认证、验证码、API Key、Casbin RBAC 权限控制
- **阻断日志**：实时记录阻断事件，支持统计和查询
- **事件上报**：可配置的 eBPF 事件采样上报机制
- **WAF 联动**：监控 Caddy + Coraza WAF 日志，自动触发 IP 封禁并定期清理

### 黑名单规则来源（位掩码）

多源规则通过位掩码实现聚合管理，同一 IP 可被多个来源同时封禁，掩码通过 `|=` 合并：

| 来源 | 说明 | 位掩码 | 状态 |
|------|------|--------|------|
| IPSum | 第三方威胁情报源 | `0x01` | ✅ 已实现 |
| Spamhaus | 国际知名垃圾邮件黑名单 | `0x02` | ✅ 已实现 |
| 手动规则 | 通过 API 手动添加的 IP/CIDR 规则 | `0x04` | ✅ 已实现 |
| WAF 自动封禁 | 监控 WAF 审计日志自动封禁 IP | `0x08` | ✅ 已实现 |
| DDoS 防护 | 异常流量检测自动封禁 | `0x10` | ✅ 已实现 |
| 频率限制封禁 | 监控 Rate Limit 日志自动封禁 | `0x20` | ✅ 已实现 |
| 异常流量检测 | 基于采样的异常流量模式检测 | `0x40` | ✅ 已实现 |
| SSH 防爆破 | 监控 SSH 认证失败自动封禁 | `0x80` | ✅ 已实现 |

> **注意**：IP 白名单使用独立的 map 存储，不参与位掩码体系。Geo-Blocking 使用专用的 eBPF map 实现地域过滤，也不在位掩码管理范围内。

## 开发环境

1. 设置GOPROXY
```bash
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct
```

2. 安装必要开发环境
```bash
apt update
apt install  bpftool libbpf-dev llvm clang libelf-dev gcc-multilib build-essential
```

## 快速开始

### 系统要求

- Linux 内核 5.8+（支持 XDP）
- Go 1.25+
- root 权限或 CAP_BPF 能力
- clang/LLVM（用于编译 eBPF 程序）

### WAF IP 封禁清理机制

WAF 模块通过监控 Caddy + Coraza WAF 日志和 Rate Limit 日志，自动触发 IP 封禁。封禁的完整生命周期如下：

```
日志触发 → banIP() 添加 XDP 封禁规则 → 封禁记录写入内存（带过期时间）
                                                    ↓
                                        cleanupExpiredBans() 每隔 5 分钟扫描
                                                    ↓
                                        过期 IP 移除 XDP 规则 + 清除内存记录
```

> ⚠️ **重要：清理间隔为固定 5 分钟**

`cleanupExpiredBans()` 使用硬编码的 **5 分钟清理间隔**。当封禁到期后，XDP 规则不会立即移除，而是等待下一个清理周期才执行移除。

这意味着实际封禁时长 = `BanDuration` + 最多 5 分钟的清理延迟。

**配置建议：**

| BanDuration | 实际封禁时长范围 | 建议 |
|-------------|------------------|------|
| 30s | 30s ~ 5m30s | ❌ 不推荐，XDP 规则滞留过久 |
| 60s | 60s ~ 6m | ⚠️ 清理延迟占比过大 |
| 300s（5 分钟） | 5m ~ 10m | ✅ 可接受 |
| 600s（10 分钟） | 10m ~ 15m | ✅ 推荐 |
| 3600s（1 小时，默认） | 1h ~ 1h5m | ✅ 推荐 |

**最佳实践：** 建议将 `ban_duration` 设置为 **300 秒（5 分钟）或更长**，使清理延迟在整体封禁时长中的占比合理。

### 使用预构建镜像部署

```bash
# 直接启动（拉取预构建镜像）
docker compose up -d

# 查看日志
docker compose logs -f
```

### 从源码构建部署

```bash
# 从源码构建并启动
docker compose -f docker-compose-build-run.yml up -d --build

# 查看日志
docker compose -f docker-compose-build-run.yml logs -f
```

### 安全说明

- **rho-aias** 使用最小权限能力（`CAP_BPF`、`CAP_PERFMON`、`CAP_NET_ADMIN`、`CAP_NET_RAW`），不使用 privileged 模式
- **caddy** 仅保留 `NET_BIND_SERVICE` 能力，并启用 `no-new-privileges` 安全选项
- 两个容器均使用 `network_mode: host` 以支持 XDP 驱动层拦截
- WAF 日志通过只读卷共享给 rho-aias（`/logs/caddy:/caddy-logs:ro`）


### 集成测试

`test/` 目录下提供基于 Python 的 XDP 阻断集成测试：

- `test/netns.py` - 网络命名空间设置脚本
- `test/run_tests.sh` - 测试运行脚本
- `test/test_xdp_block.py` - XDP 阻断功能集成测试

详见 [test/README.md](test/README.md)。
