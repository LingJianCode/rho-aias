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
- **认证与授权**：JWT 认证、验证码、API Key、Casbin RBAC 权限控制

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
│  │  认证: /api/auth/*                                            │   │
│  │  手动规则: GET/POST/DELETE /api/manual/rules                  │   │
│  │  情报: GET/POST /api/intel/status, /api/intel/update         │   │
│  │  地域封禁: GET/POST /api/geoblocking/*                        │   │
│  │  阻断日志: GET/DELETE /api/blocklog/*                         │   │
│  │  用户管理: GET/POST/PUT/DELETE /api/users/*                  │   │
│  │  API Key: GET/POST/DELETE /api/api-keys/*                    │   │
│  │  审计日志: GET/POST /api/audit/*                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## 项目结构

```
rho-aias/
├── main.go                       # 主程序入口
├── config.yml                    # 配置文件（端口、网卡、威胁情报）
├── go.mod                        # Go 模块依赖
├── makefile                      # 构建脚本
├── ebpfs/                        # eBPF C 源码
│   ├── xdp.bpf.c                 # XDP 程序
│   ├── common.h                  # 公共常量定义
│   └── vmlinux.h                 # 内核头文件（自动生成）
├── internal/
│   ├── auth/                     # 认证模块
│   │   ├── jwt/                  # JWT 服务
│   │   ├── captcha/              # 验证码服务
│   │   ├── apikey/               # API Key 认证
│   │   └── password/             # 密码加密
│   ├── blocklog/                 # 阻断日志模块
│   ├── casbin/                   # Casbin RBAC 权限管理
│   ├── config/                   # 配置管理
│   ├── database/                 # SQLite 数据库
│   ├── ebpfs/                    # eBPF Go 封装
│   │   ├── gen.go                # bpf2go 生成指令
│   │   ├── xdp.go                # XDP 生命周期管理
│   │   ├── xdp_type.go           # XDP 类型定义
│   │   └── net_type.go           # 网络类型定义
│   ├── geoblocking/              # 地域封禁模块
│   ├── handles/                  # API 处理器
│   ├── manual/                   # 手动规则模块
│   ├── middleware/               # HTTP 中间件
│   ├── models/                   # 数据模型
│   ├── routers/                  # 路由注册
│   ├── services/                 # 业务逻辑服务
│   └── threatintel/              # 威胁情报模块
├── config/                       # 配置示例
└── utils/                        # 工具函数
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

# 认证配置
auth:
  enabled: true                    # 是否启用认证
  jwt_secret: ""                   # JWT 密钥，建议从环境变量 JWT_SECRET 读取
  jwt_issuer: "rho-aias"           # JWT 签发者
  token_duration: 1440             # Token 有效期（分钟），默认 24 小时
  database_path: "./data/auth.db"  # 数据库路径
  captcha_enabled: true            # 是否启用验证码
  captcha_duration: 5              # 验证码有效期（分钟）

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

### 认证 API

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/api/auth/captcha` | 获取验证码 | 公开 |
| POST | `/api/auth/login` | 用户登录 | 公开 |
| POST | `/api/auth/refresh` | 刷新 Token | 公开 |
| POST | `/api/auth/logout` | 用户登出 | 公开 |
| GET | `/api/auth/me` | 获取当前用户信息 | 需认证 |
| PUT | `/api/auth/password` | 修改密码 | 需认证 |

**默认凭证：** 首次启动时自动创建管理员账户：
- 用户名：`admin`
- 密码：`admin123`

> ⚠️ **重要：** 首次登录后请立即修改默认密码！

**登录示例：**

```bash
# 1. 获取验证码
curl http://localhost:8080/api/auth/captcha
# 返回: {"captcha_id": "xxx", "image": "data:image/png;base64,..."}

# 2. 登录
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123", "captcha_id": "xxx", "captcha_answer": "abcd"}'
# 返回: {"token": "eyJhbGciOiJIUzI1NiIs...", "user": {...}, "expires_at": "..."}

# 3. 访问受保护的 API
curl http://localhost:8080/api/manual/rules \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### 手动规则 API

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/api/manual/rules` | 获取所有规则 | firewall:read |
| POST | `/api/manual/rules` | 添加过滤规则 | firewall:write |
| DELETE | `/api/manual/rules` | 删除规则 | firewall:write |

**请求示例：**

```bash
# 添加规则
curl -X POST http://localhost:8080/api/manual/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"value": "192.168.1.1"}'

# 获取规则
curl http://localhost:8080/api/manual/rules \
  -H "Authorization: Bearer <token>"

# 删除规则
curl -X DELETE http://localhost:8080/api/manual/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"value": "192.168.1.1"}'
```

### 威胁情报 API

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/api/intel/status` | 获取威胁情报状态 | intel:read |
| POST | `/api/intel/update` | 手动触发更新 | intel:write |

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

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/api/geoblocking/status` | 获取地域封禁状态 | geo:read |
| POST | `/api/geoblocking/update` | 手动触发 GeoIP 更新 | geo:write |
| POST | `/api/geoblocking/config` | 更新配置（模式、国家） | geo:write |

### 阻断日志 API

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/api/blocklog/records` | 获取阻断记录列表 | blocklog:read |
| GET | `/api/blocklog/stats` | 获取阻断统计 | blocklog:read |
| GET | `/api/blocklog/blocked-ips` | 获取阻断 IP 列表 | blocklog:read |
| GET | `/api/blocklog/blocked-countries` | 获取阻断国家列表 | blocklog:read |
| DELETE | `/api/blocklog/records` | 清除所有阻断记录 | blocklog:clear |

### 用户管理 API

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/api/users` | 获取用户列表 | admin:* |
| POST | `/api/users` | 创建用户 | admin:* |
| GET | `/api/users/:id` | 获取用户详情 | admin:* |
| PUT | `/api/users/:id` | 更新用户 | admin:* |
| DELETE | `/api/users/:id` | 删除用户 | admin:* |

### API Key 管理 API

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/api/api-keys` | 获取 API Key 列表 | api_key:manage |
| POST | `/api/api-keys` | 创建 API Key | api_key:manage |
| DELETE | `/api/api-keys/:id` | 吊销 API Key | api_key:manage |

### 审计日志 API

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/api/audit/logs` | 获取审计日志列表 | admin:* |
| GET | `/api/audit/logs/:id` | 获取单条审计日志 | admin:* |
| POST | `/api/audit/clean` | 清理旧审计日志 | admin:* |

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

# 运行单元测试
go test -v -coverprofile=coverage.out ./...

# 查看测试覆盖率
go tool cover -html=coverage.out

# 生成 vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h
```

## 测试

项目包含单元测试，覆盖核心模块：

- `utils/net_test.go` - 网络工具测试
- `internal/threatintel/*_test.go` - 威胁情报模块测试
- `internal/geoblocking/*_test.go` - 地域封禁模块测试
- `internal/auth/*_test.go` - 认证模块测试
- `internal/manual/*_test.go` - 手动规则模块测试
- `internal/blocklog/blocklog_test.go` - 阻断日志模块测试
- `internal/middleware/auth_test.go` - 中间件测试

**运行测试：**
```bash
go test -v ./...
```

## 安全建议

1. **JWT Secret**：生产环境务必设置强密钥：
   ```bash
   export JWT_SECRET="your-strong-secret-key-here"
   ```

2. **默认密码**：首次登录后立即修改默认管理员密码

3. **HTTPS**：生产环境建议使用 HTTPS

4. **Token 存储**：客户端应安全存储 Token

## 已知问题

1. **MD5 安全问题**：`utils/net.go` 中使用 MD5，建议改用 SHA256
2. **多源规则删除**：禁用威胁情报源时，多源共有规则不会按位删除
