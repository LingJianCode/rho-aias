# rho-aias

**rho-aias** 是一个基于 eBPF 和 XDP（eXpress Data Path）技术的高性能网络防火墙系统，在网络驱动层（L2/L3）拦截和过滤数据包，相比传统的 netfilter/iptables 具有更优的性能。

## 功能特性

### 核心功能

- **eBPF XDP 包过滤**：在驱动层实现高性能数据包拦截
- **多源规则管理**：支持手动规则、威胁情报、地域封禁等多种规则来源
- **位掩码追踪**：通过位掩码标记规则来源，避免多源冲突
- **RESTful API**：提供完整的 HTTP API 进行规则管理
- **持久化存储**：规则自动持久化到本地，支持离线启动
- **Cron 定时任务**：支持独立的定时更新调度

### 规则来源

| 来源 | 说明 | 状态 |
|------|------|------|
| 手动规则 | 通过 API 手动添加的 IP/CIDR/MAC 规则 | ✅ 已实现 |
| IPSum | 第三方威胁情报源（~23万条规则） | ✅ 已实现 |
| Spamhaus DROP | 国际知名垃圾邮件黑名单 | ✅ 已实现 |
| Geo-Blocking | 基于国家/地区的地域封禁 | ✅ 已实现 |

## 架构设计

```
┌─────────────────────────────────────────────────────────────────────┐
│                         网络数据包流程                               │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  XDP 程序 (ebpfs/xdp.bpf.c)                                   │   │
│  │  - 最早拦截点（驱动层）                                        │   │
│  │  - 按以下方式过滤：IP/MAC（L2/L3层）                            │   │
│  │  - Maps: ipv4_list, ipv4_cidr_trie, ipv6_list, ipv6_cidr_trie│   │
│  │  - 返回: XDP_DROP（丢弃）或 XDP_PASS（放行）                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓ (if XDP_PASS)                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Go 用户空间 (internal/ebpfs/)                                │   │
│  │  - xdp.go: XDP 生命周期和规则管理                              │   │
│  │  - 通过 bpf2go 从 C 源码生成                                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  威胁情报模块 (internal/threatintel/)                         │   │
│  │  - intel.go: 情报管理器和调度器                                │   │
│  │  - fetcher.go: 从外部源获取数据                                │   │
│  │  - parser.go: 解析 IPSum/Spamhaus 格式                        │   │
│  │  - sync.go: 原子同步到内核 eBPF maps                           │   │
│  │  - cache.go: 本地持久化，支持离线启动                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  地域封禁模块 (internal/geoblocking/)                         │   │
│  │  - geoblocking.go: 地域管理器和调度器                          │   │
│  │  - fetcher.go: 从 nginx 获取 GeoIP 数据                        │   │
│  │  - parser.go: 解析 MaxMind/DB-IP 格式                         │   │
│  │  - sync.go: 原子同步到内核 eBPF maps                           │   │
│  │  - cache.go: 本地持久化，支持离线启动                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  HTTP API (internal/handles/, internal/routers/)             │   │
│  │  路由 (RESTful /api/{module}/{action}):                      │   │
│  │  手动规则: GET/POST/DELETE /api/manual/rules                 │   │
│  │  情报: GET/POST /api/intel/status, /api/intel/update         │   │
│  │  地域封禁: GET/POST /api/geoblocking/status,                  │   │
│  │              /api/geoblocking/update, /api/geoblocking/config  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## 项目结构

```
rho-aias/
├── main.go                       # 主程序入口
├── config.yml                    # 配置文件（端口、网卡、威胁情报）
├── go.mod                        # Go 模块依赖
├── Makefile                      # 构建脚本
├── ebpfs/                        # eBPF C 源码
│   ├── xdp.bpf.c                 # XDP 程序
│   ├── common.h                  # 公共常量定义
│   └── vmlinux.h                 # 内核头文件（自动生成）
├── internal/
│   ├── config/
│   │   └── config.go             # 配置管理
│   ├── ebpfs/
│   │   ├── gen.go                # bpf2go 生成指令
│   │   ├── xdp.go                # XDP 生命周期管理
│   │   ├── xdp_type.go           # XDP 类型定义
│   │   └── net_type.go           # 网络类型定义
│   ├── threatintel/              # 威胁情报模块
│   ├── manual/                   # 手动规则模块
│   ├── geoblocking/              # 地域封禁模块
│   ├── handles/                  # API 处理器
│   └── routers/                  # 路由注册
├── test/                         # 测试工具
├── utils/                        # 工具函数
└── scripts/                      # 快速脚本
```

## 快速开始

### 系统要求

- Linux 内核 5.8+（支持 XDP）
- Go 1.21+
- root 权限或 CAP_BPF 能力
- clang/LLVM（用于编译 eBPF 程序）

### 安装

```bash
# 克隆仓库
git clone <repository-url>
cd rho-aias

# 生成 eBPF Go 代码
make gen

# 编译程序
make build
```

### 配置

编辑 `config.yml` 文件：

```yaml
server:
  port: 8080                    # HTTP API 端口
ebpf:
  interface_name: ens33         # 网络接口名称

# 威胁情报配置
intel:
  enabled: true
  persistence_dir: ./data/intel
  batch_size: 1000
  sources:
    ipsum:
      enabled: true
      schedule: "0 1 * * *"    # Cron 表达式
      url: http://localhost/ipsum.txt
      format: ipsum
    spamhaus:
      enabled: true
      schedule: "0 2 * * *"
      url: http://localhost/drop.txt
      format: spamhaus

# 地域封禁配置
geo_blocking:
  enabled: true
  mode: whitelist               # whitelist 或 blacklist
  allowed_countries:
    - CN                        # 允许的国家代码
  allow_private_networks: true  # 允许私有网段绕过检查
  persistence_dir: ./data/geo
  batch_size: 1000
  sources:
    maxmind:
      enabled: true
      schedule: "0 3 * * *"
      url: http://localhost/GeoLite2-Country.mmdb
      format: maxmind-db

# 手动规则配置
manual:
  enabled: true
  persistence_dir: ./data/manual
  auto_load: true              # 启动时自动加载
```

### 运行

```bash
# 需要 root 权限
sudo ./rho-aias
```

## API 接口

### 手动规则 API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/manual/rules` | 获取所有规则及来源信息 |
| POST | `/api/manual/rules` | 添加过滤规则 |
| DELETE | `/api/manual/rules` | 删除规则 |

**请求示例：**

```bash
# 添加规则
curl -X POST http://localhost:8080/api/manual/rules \
  -H "Content-Type: application/json" \
  -d '{"value": "192.168.1.1"}'

# 获取规则
curl http://localhost:8080/api/manual/rules

# 删除规则
curl -X DELETE http://localhost:8080/api/manual/rules \
  -H "Content-Type: application/json" \
  -d '{"value": "192.168.1.1"}'
```

### 威胁情报 API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/intel/status` | 获取威胁情报状态 |
| POST | `/api/intel/update` | 手动触发更新 |

**状态响应示例：**

```json
{
  "enabled": true,
  "last_update": "2024-01-15T10:30:00Z",
  "total_rules": 15234,
  "sources": {
    "ipsum": {
      "enabled": true,
      "last_update": "2024-01-15T10:00:00Z",
      "success": true,
      "rule_count": 15000,
      "error": ""
    },
    "spamhaus": {
      "enabled": true,
      "last_update": "2024-01-14T02:00:00Z",
      "success": true,
      "rule_count": 234,
      "error": ""
    }
  }
}
```

### 地域封禁 API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/geoblocking/status` | 获取地域封禁状态 |
| POST | `/api/geoblocking/update` | 手动触发 GeoIP 更新 |
| POST | `/api/geoblocking/config` | 更新配置（模式、国家） |

## 规则格式

系统支持以下规则格式：

- **IPv4 地址**: `192.168.1.1`
- **IPv4 CIDR**: `192.168.1.0/24`
- **IPv6 地址**: `2001:db8::1`
- **IPv6 CIDR**: `2001:db8::/32`
- **MAC 地址**: `00:11:22:33:44:55`

## Cron 表达式

威胁情报和 GeoIP 数据源支持独立的 Cron 定时任务：

```
┌───────────── 分钟 (0 - 59)
│ ┌───────────── 小时 (0 - 23)
│ │ ┌───────────── 日期 (1 - 31)
│ │ │ ┌───────────── 月份 (1 - 12)
│ │ │ │ ┌───────────── 星期 (0 - 6) (周日 = 0)
│ │ │ │ │
* * * * *
```

**常用示例：**
- `0 * * * *` - 每小时整点
- `0 */6 * * *` - 每 6 小时
- `0 2 * * *` - 每天凌晨 2 点
- `0 0 * * 0` - 每周日午夜
- `*/30 * * * *` - 每 30 分钟

## 快速脚本

项目提供了一组快速脚本用于手动规则管理：

```bash
# 添加规则
./scripts/add.sh

# 删除规则
./scripts/del.sh

# 获取所有规则
./scripts/get.sh

# 内核监控
./scripts/monitor.sh
```

## 性能优化

XDP eBPF 程序经过多项性能优化：

| 优化项 | 预期提升 | 适用场景 |
|--------|----------|----------|
| 分支预测提示 | 2-5% | 所有数据包 |
| 减少 memset/memcpy | 5-10% | IPv6 数据包 |
| IPv6 早期退出 | 5-15% | IPv6 数据包 |
| 选择性字段初始化 | 1-3% | 所有数据包 |

**总体提升：** 混合流量 5-15%，IPv6 重度负载可达 20%

## 开发命令

```bash
# 生成 eBPF Go 代码（修改 .bpf.c 后需要）
make gen

# 编译
make build

# 运行
make run

# 清理
make clean

# 生成 vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h
```

## 测试工具

### IPv4 测试

```bash
# 运行所有 IPv4 测试
sudo python3 test/test_ipv4.py <target_ip> all

# 特定测试
sudo python3 test/test_ipv4.py <target_ip> ipv4_malformed_short_header
```

### IPv6 测试

```bash
# 运行所有 IPv6 测试
sudo python3 test/test_ipv6.py <target_ip> all

# 特定测试
sudo python3 test/test_ipv6.py <target_ip> ipv6_ext_hbh
```

## 许可证

Dual MIT/GPL

## 已知问题

目前没有已知问题。

## 贡献

欢迎提交 Issue 和 Pull Request！
