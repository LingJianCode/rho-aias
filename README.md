# rho-aias

基于 eBPF/XDP 的高性能网络防火墙系统，在网络驱动层（L3）拦截和过滤数据包。

## 功能特性

- **eBPF XDP 包过滤**：驱动层高性能拦截
- **威胁情报**：IPSum / Spamhaus 等多源黑名单自动同步
- **地域封禁**：GeoIP 国家级白名单/黑名单过滤
- **手动规则**：支持通过 API 添加 IP/CIDR 封禁规则
- **WAF 联动**：监控 Caddy + Coraza WAF 日志，自动封禁恶意 IP
- **SSH 防爆破**：类 fail2ban 机制，自动检测并封禁暴力破解
- **异常流量检测**：SYN Flood / UDP Flood / ICMP Flood / ACK Flood 等攻击自动识别与阻断
- **频率限制联动**：监控 Rate Limit 日志，高频请求自动封禁
- **RESTful API**：完整的管理接口（JWT 认证 + RBAC 权限控制）
- **持久化存储**：规则自动落盘，支持离线启动

## 前置条件

| 要求 | 说明 |
|------|------|
| Linux 内核 | **5.10+**（需支持 XDP 与 BTF） |
| Docker | **24.0+** 及 Docker Compose v2 |
| 网络权限 | 需 `host` 网络模式 + 特定 Linux Capability |
| 网卡 | 需确认本机网卡名称（如 `ens33`、`eth0`） |

> ⚠️ 本项目依赖 eBPF XDP 技术，**仅支持 Linux 系统**，不支持 macOS / Windows。

## 使用方法

### 方式一：使用预构建镜像（推荐）

1. **克隆项目**

```bash
git clone
cd rho-aias
```

2. **修改网卡名称**

编辑 `config/config.yml`，将 `interface_name` 修改为你的实际网卡名称：

```yaml
ebpf:
  interface_name: ens33   # ← 改为实际网卡名，如 eth0、enp0s3 等
```

3. **启动服务**

```bash
docker compose up -d
```

4. **验证**

```bash
# 查看 rho-aias 服务日志
docker compose logs -f rho-aias

# 访问 Web 服务测试（Caddy 默认监听 80 端口）
curl localhost
curl localhost/.svn    # 应返回 403（WAF 规则生效）
```

### 方式二：从源码构建

```bash
git clone
cd rho-aias

# 同样需要先修改 config/config.yml 中的网卡名称

docker compose -f docker-compose-build-run.yml up -d --build
docker compose -f docker-compose-build-run.yml logs -f
```

## 配置说明

主要配置文件为 [`config/config.yml`](config/config.yml)，常用项：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `server.port` | API 服务端口 | 8081 |
| `ebpf.interface_name` | 监听的网卡名称 | ens33 |
| `intel.sources.*` | 威胁情报源开关及更新计划 | 已启用 |
| `geo_blocking.enabled` | 地域封禁开关 | false |
| `waf.enabled` | WAF 联动封禁开关 | true |
| `failguard.enabled` | SSH 防爆破开关 | true |
| `anomaly_detection.enabled` | 异常流量检测开关 | true |
| `auth.api_keys` | API Key 认证配置 | 已预设 |

详细配置说明见 `config/config.yml` 内联注释。

## 安全说明

- **rho-aias** 容器使用最小权限能力（`CAP_BPF`、`CAP_PERFMON`、`CAP_NET_ADMIN`、`CAP_NET_RAW`），不使用 privileged 模式
- **caddy** 容器仅保留 `NET_BIND_SERVICE` 能力，启用 `no-new-privileges`
- 两个容器均使用 `network_mode: host` 以支持 XDP 驱动层拦截
