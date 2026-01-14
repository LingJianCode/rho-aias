# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**rho-aias** is a high-performance eBPF network firewall with XDP (eXpress Data Path) packet filtering and integrated threat intelligence. It intercepts and filters network packets at the driver level (L2/L3) using:
- Manual rules configured via REST API
- Automated threat intelligence feeds (IPSum, Spamhaus DROP)
- Multi-source rule tracking with bitmask tagging (prevents conflicts)

The system consists of:

1. **eBPF XDP program** (`ebpfs/xdp.bpf.c`) - Packet filtering at driver level
2. **Go userspace controller** - Manages eBPF lifecycle and provides REST API
3. **Manual Rules module** - Persistent manual rule management with auto-load on startup
4. **Threat Intelligence module** - Auto-syncs external threat feeds
5. **Geo-Blocking module** - Country-based IP filtering (whitelist/blacklist)
6. **Gin HTTP server** - REST API for rule, threat intel, and geo-blocking management
7. **Configuration system** - Port, interface, threat intel, geo-blocking, and manual rules configurable via `config.yml`

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Network Packet Flow                          │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  XDP Program (ebpfs/xdp.bpf.c)                               │   │
│  │  - Earliest hook (driver level)                              │   │
│  │  - Filters by: IP/MAC (L2/L3)                                │   │
│  │  - Maps: ipv4_list, ipv4_cidr_trie, ipv6_list, ipv6_cidr_trie│   │
│  │  - Returns: XDP_DROP or XDP_PASS                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓ (if XDP_PASS)                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Go Userspace (internal/ebpfs/)                              │   │
│  │  - xdp.go: XDP lifecycle and rule management                 │   │
│  │  - Loaded via bpf2go from C sources                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Threat Intelligence (internal/threatintel/)                │   │
│  │  - intel.go: Threat intel manager and scheduler               │   │
│  │  - fetcher.go: Fetches data from external sources             │   │
│  │  - parser.go: Parses IPSum/Spamhaus formats                │   │
│  │  - sync.go: Atomic sync to kernel eBPF maps                  │   │
│  │  - cache.go: Local persistence for offline startup             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Geo-Blocking (internal/geoblocking/)                        │   │
│  │  - geoblocking.go: Geo-blocking manager and scheduler        │   │
│  │  - fetcher.go: Fetches GeoIP CSV from nginx                   │   │
│  │  - parser.go: Parses MaxMind/DB-IP formats                   │   │
│  │  - sync.go: Atomic sync to kernel eBPF maps                  │   │
│  │  - cache.go: Local persistence for offline startup             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  HTTP API (internal/handles/, internal/routers/)             │   │
│  │  Routes (RESTful /api/{module}/{action}):                   │   │
│  │  Manual: GET/POST/DELETE /api/manual/rules                   │   │
│  │  Intel: GET/POST /api/intel/status, /api/intel/update        │   │
│  │  GeoBlocking: GET/POST /api/geoblocking/status,              │   │
│  │              /api/geoblocking/update, /api/geoblocking/config  │   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Project Structure

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
│   │   ├── xdp_bpfel.go          # 自动生成（小端序）
│   │   ├── xdp_bpfeb.go          # 自动生成（大端序）
│   │   ├── xdp_type.go           # XDP 类型定义
│   │   └── net_type.go           # 网络类型定义
│   ├── threatintel/              # 威胁情报模块
│   │   ├── types.go              # 类型定义
│   │   ├── fetcher.go            # 数据获取器
│   │   ├── parser.go             # 数据解析器
│   │   ├── cache.go              # 本地持久化
│   │   ├── sync.go               # 内核同步
│   │   └── intel.go              # 情报管理器
│   ├── manual/                   # 手动规则模块
│   │   ├── types.go              # 类型定义
│   │   └── cache.go              # 本地持久化
│   ├── geoblocking/              # 地域封禁模块
│   │   ├── types.go              # 类型定义
│   │   ├── fetcher.go            # GeoIP 数据获取器
│   │   ├── parser.go             # GeoIP 数据解析器
│   │   ├── cache.go              # 本地持久化
│   │   ├── sync.go               # 内核同步
│   │   └── geoblocking.go       # 地域封禁管理器
│   ├── handles/
│   │   ├── manual.go             # 手动规则 API 处理器 (原 xdp.go)
│   │   ├── manual_req.go         # 请求结构体
│   │   ├── intel.go              # 威胁情报 API 处理器
│   │   └── geoblocking.go        # 地域封禁 API 处理器
│   └── routers/
│       ├── manual.go             # 手动规则路由注册 (原 xdp.go)
│       ├── intel.go              # 威胁情报路由注册
│       └── geoblocking.go        # 地域封禁路由注册
├── test/
│   ├── README.md                  # 测试说明
│   ├── test_ipv4.py              # IPv4 测试工具
│   └── test_ipv6.py              # IPv6 测试工具
├── utils/
│   ├── net.go                    # 网络工具函数
│   └── net_test.go               # 网络工具测试
└── scripts/
    ├── add.sh                     # 添加规则脚本
    ├── del.sh                     # 删除规则脚本
    ├── get.sh                     # 获取规则脚本
    └── monitor.sh                 # 内核监控脚本
```

## Threat Intelligence Module

The `internal/threatintel/` module integrates external threat intelligence feeds:

### Features

1. **Multi-source Support**
   - IPSum: https://github.com/stamparm/ipsum
   - Spamhaus DROP: https://www.spamhaus.org/drop/
   - Manual (API-added rules)
   - Future: WAF, DDoS Detection

2. **Per-Source Cron Scheduling**
   - Each threat intel source has its own independent Cron schedule
   - Standard 5-field Cron syntax (minute hour day month weekday)
   - Example: IPSum updates daily at 1 AM, Spamhaus updates daily at 2 AM
   - Powered by `github.com/robfig/cron/v3`

3. **Source-Aware Rule Management**
   - Bitmask tagging tracks rule ownership across sources
   - No conflicts when same IP appears in multiple feeds
   - Per-source enable/disable without affecting other sources
   - Manual rules persist even when threat intel sources are disabled

4. **Automatic Synchronization**
   - Per-source Cron-based scheduling (flexible timing)
   - Incremental atomic updates (no interception gap)
   - Source-aware diff calculation
   - Failure handling: no retry, wait for next scheduled run

5. **Local Persistence**
   - Binary gob format cache
   - Offline startup support
   - Cache directory: `./data/intel/`

6. **High-Performance Batch Updates**
   - Batch size configurable (default: 1000 rules)
   - Incremental diff algorithm with source awareness
   - Concurrent-safe operations

7. **Optimized Cache Loading**
   - `LoadAll()` method skips GetRule() and diff calculation for initial load
   - Direct batch insertion for fastest startup performance
   - Suitable for empty kernel scenarios (offline startup)

### Configuration

Add to `config.yml`:

```yaml
intel:
  enabled: true                      # 总开关
  persistence_dir: ./data/intel      # 持久化目录
  batch_size: 1000                   # 批量更新大小
  sources:
    ipsum:
      enabled: true
      schedule: "0 1 * * *"          # 每天凌晨 1 点更新 (Cron 表达式)
      url: https://raw.githubusercontent.com/stamparm/ipsum/main/ipsum.txt
      format: ipsum
    spamhaus:
      enabled: false
      schedule: "0 2 * * *"          # 每天凌晨 2 点更新
      url: https://www.spamhaus.org/drop/drop.txt
      format: spamhaus
```

**Cron Expression Format:**
```
┌───────────── 分钟 (0 - 59)
│ ┌───────────── 小时 (0 - 23)
│ │ ┌───────────── 日期 (1 - 31)
│ │ │ ┌───────────── 月份 (1 - 12)
│ │ │ │ ┌───────────── 星期 (0 - 6) (周日 = 0)
│ │ │ │ │
* * * * *
```

**Common Examples:**
- `0 * * * *` - 每小时整点
- `0 */6 * * *` - 每 6 小时
- `0 2 * * *` - 每天凌晨 2 点
- `0 0 * * 0` - 每周日午夜
- `*/30 * * * *` - 每 30 分钟

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/intel/status` | Get threat intel status |
| POST | `/api/intel/update` | Manually trigger update |

### Data Format Support

**IPSum Format:**
```
# IPsum Threat Intelligence Feed
5.187.35.21     11
31.59.129.85    10
```

**Spamhaus DROP Format:**
```
; Spamhaus DROP List
1.10.16.0/20 ; SBL256894
1.19.0.0/16 ; SBL434604
```

## Geo-Blocking Module

The `internal/geoblocking/` module provides country-based IP filtering:

### Features

1. **Fail-Open Safety**
   - Whitelist mode only activates when data is successfully loaded (`TotalCount() > 0`)
   - Prevents network outage if GeoIP data fetch fails
   - Initial state: `enabled=0` → Pass all (waiting for data)
   - Data loaded successfully: `enabled=1` → Filter normally

2. **IPv4 Only**
   - Supports IPv4 CIDR matching via LPM trie
   - Max capacity: 500,000 entries (for GeoLite2-Country.mmdb)
   - IPv6 networks are filtered out during parsing (MMDB contains both IPv4 and IPv6)
   - IPv6 traffic passes through (not filtered by geo-blocking)

3. **Dual Mode Support**
   - **Whitelist**: Only allow specified countries
   - **Blacklist**: Block specified countries

4. **MaxMind/DB-IP Integration**
   - Supports both CSV and MMDB (MaxMind DB binary) formats
   - MMDB format uses `github.com/oschwald/maxminddb-golang`
   - Data fetched from nginx file server
   - Per-source Cron scheduling
   - Local persistence for offline startup
   - Cache directory: `./data/geo/`

5. **Private Network Bypass**
   - Optional bypass for RFC 1918 private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Uses special country code "PN" (Private Network = 0x504E0000)
   - Controlled by `allow_private_networks` configuration
   - Added to whitelist during `SyncToKernel()` and `LoadAll()`
   - **Configuration only** - not persisted in cache

6. **Cache Design**
   - Cache stores only GeoIP data (CIDR-country pairs)
   - Configuration items (`Mode`, `AllowedCountries`, `AllowPrivateNetworks`) are read from `config.yml`
   - Changing configuration takes effect immediately (no cache deletion needed)

### Configuration

Add to `config.yml`:

```yaml
geo_blocking:
  enabled: true                          # 总开关
  mode: whitelist                         # whitelist 或 blacklist
  allowed_countries:
    - CN                                  # 允许的国家代码
  allow_private_networks: true            # 允许私有网段绕过地域检查（RFC 1918）
  persistence_dir: ./data/geo             # 持久化目录
  batch_size: 1000                        # 批量更新大小
  sources:
    maxmind:
      enabled: true
      schedule: "0 3 * * *"                # 每天凌晨 3 点
      url: "http://nginx-server/GeoLite2-Country.mmdb"
      format: maxmind-db                   # maxmind (CSV) 或 maxmind-db (MMDB)
```

**Data Format Options:**
- `maxmind`: MaxMind CSV format (`network,registered_country_iso_code,...`)
- `maxmind-db`: MaxMind DB binary format (MMDB) - recommended for production
- `dbip`: DB-IP CSV format (future)

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/geoblocking/status` | Get geo-blocking status |
| POST | `/api/geoblocking/update` | Manually trigger GeoIP update |
| POST | `/api/geoblocking/config` | Update configuration (mode, countries) |

**Status response format:**
```json
{
  "enabled": true,              // 实际是否在过滤（数据已加载）
  "mode": "whitelist",
  "allowed_countries": ["CN"],
  "last_update": "2024-01-15T10:00:00Z",
  "total_rules": 15000,
  "sources": {
    "maxmind": {
      "enabled": true,
      "last_update": "2024-01-15T10:00:00Z",
      "success": true,
      "rule_count": 15000,
      "error": ""
    }
  }
}
```

### Data Format

**MaxMind CSV Format:**
```
network,registered_country_iso_code,...
1.0.0.0/24,CN,...
2.0.0.0/24,US,...
```

**MaxMind DB (MMDB) Format:**
- Binary format for efficient lookups
- Requires `github.com/oschwald/maxminddb-golang`
- GeoLite2-Country.mmdb contains both IPv4 and IPv6 networks
- IPv6 networks are automatically filtered out during parsing
- Use `maxmind-db` format in configuration

Only countries in `allowed_countries` are loaded into the kernel, reducing memory usage.

## Manual Rules Module

The `internal/manual/` module provides persistent manual rule management:

### Features

1. **Rule Persistence**
   - Manual rules are persisted to disk using gob binary format
   - Cache file: `./data/manual/manual_cache.bin`
   - Rules survive server restarts

2. **Auto-Load on Startup**
   - When `auto_load: true`, rules are automatically loaded on startup
   - Loaded rules are added to eBPF maps with MANUAL source bit (0x04)

3. **RESTful API**
   - All endpoints use `/api/manual/rules` prefix
   - Consistent with other modules (intel, geoblocking)

### Configuration

Add to `config.yml`:

```yaml
manual:
  enabled: true                  # Enable manual rule persistence
  persistence_dir: ./data/manual  # Cache directory
  auto_load: true                # Auto-load rules on startup
```

### Cache Data Structure

```go
type CacheData struct {
    Version   uint32                       // Cache version
    Timestamp int64                        // Unix timestamp
    Rules     map[string]ManualRuleEntry  // key: value, value: entry
}

type ManualRuleEntry struct {
    Value   string    // IP/CIDR/MAC value
    AddedAt time.Time // When added
    Source  string    // Always "manual"
}
```

### Integration Points

| Operation | Behavior |
|-----------|----------|
| Startup | Load rules from cache if `auto_load: true` |
| POST /api/manual/rules | Add to eBPF + Save to cache |
| DELETE /api/manual/rules | Remove from eBPF + Remove from cache |
| GET /api/manual/rules | Return all rules from eBPF |

## Source Tracking and Bitmask Tagging

The system implements a **Bitmask Tagging** approach to track rule ownership across multiple sources, resolving conflicts when the same IP/CIDR is added by different sources.

### BlockValue Structure

All eBPF maps use `struct block_value` as the value type:

```c
/* eBPF C structure (ebpfs/common.h) */
struct block_value {
    __u32 source_mask;  /* Source bitmask - marks which sources own this rule */
    __u32 priority;     /* Priority (reserved for future use) */
    __u64 expiry;       /* Expiration timestamp (reserved for TTL support) */
} __attribute__((packed));
```

### Source Bitmask Constants

Each source occupies a unique bit position:

| Bit | Source | Constant | Value |
|-----|--------|----------|-------|
| 0 | IPSum | `SOURCE_MASK_IPSUM` | 0x01 |
| 1 | Spamhaus | `SOURCE_MASK_SPAMHAUS` | 0x02 |
| 2 | Manual (API) | `SOURCE_MASK_MANUAL` | 0x04 |
| 3 | WAF (future) | `SOURCE_MASK_WAF` | 0x08 |
| 4 | DDoS Detection (future) | `SOURCE_MASK_DDoS` | 0x10 |
| 5-7 | Reserved | `SOURCE_MASK_RESERVED` | 0xE0 |

### Conflict Resolution

**Example: Same IP from multiple sources**
```
1. IPSum adds 1.1.1.1
   → source_mask = 0x01

2. Manual API adds 1.1.1.1
   → source_mask = 0x05 (IPSum | Manual)

3. Disable IPSum
   → source_mask = 0x04 (Manual only)

4. Delete manual rule
   → source_mask = 0x00 → rule removed
```

**Rule deletion logic:**
- Rule is deleted only when `source_mask == 0` (no owners)
- Removing a source clears its bit: `new_mask = old_mask & ~source_bit`
- If multiple sources own the rule, it persists after removing one source

### Bitmask Operations

Available helper functions in `internal/ebpfs/xdp_type.go`:

```go
// Convert source ID to bitmask
mask := SourceIDToMask("ipsum")  // returns 0x01

// Convert bitmask to source list
sources := MaskToSourceIDs(0x05)  // returns ["ipsum", "manual"]

// Bitwise operations
newMask := AddSource(0x01, "manual")        // 0x01 | 0x04 = 0x05
newMask := RemoveSource(0x05, "ipsum")      // 0x05 & ~0x01 = 0x04
hasSource := HasSource(0x05, "manual")      // true
isOnly := IsOnlySource(0x04, "manual")      // true
count := GetSourceCount(0x05)               // 2
```

### Source-Aware Synchronization

The threat intelligence module (`internal/threatintel/sync.go`) implements two sync methods:

- **`SyncToKernel(data, sourceMask)`**: Incremental sync with diff calculation
  - Calls `GetRule()` to fetch current rules
  - Calculates additions/removals using `diff()`
  - Only deletes rules when `current_mask == sourceMask` (sole ownership)
  - Multi-source rules trigger a warning and are preserved
  - **Use for**: Scheduled updates, manual triggers

- **`LoadAll(data, sourceMask)`**: Direct bulk load (optimized)
  - Skips `GetRule()` and diff calculation
  - Direct batch insertion of all rules
  - **Use for**: Startup cache loading, empty kernel initialization

## eBPF Map Structure

#### XDP Program Maps (`ebpfs/xdp.bpf.c`)

| Map | Type | Key | Value | Capacity | Purpose |
|-----|------|-----|-------|----------|---------|
| `ipv4_list` | HASH | `__be32` | `struct block_value` | 250,000 | IPv4 exact match with source tracking |
| `ipv4_cidr_trie` | LPM_TRIE | `ipv4_trie_key{prefixlen, addr}` | `struct block_value` | 10,000 | IPv4 CIDR match with source tracking |
| `ipv6_list` | HASH | `in6_addr` | `struct block_value` | 10,000 | IPv6 exact match with source tracking |
| `ipv6_cidr_trie` | LPM_TRIE | `ipv6_trie_key{prefixlen, addr}` | `struct block_value` | 10,000 | IPv6 CIDR match with source tracking |
| `geo_config` | ARRAY | `__u32` | `struct geo_config` | 1 | Geo-blocking configuration |
| `geo_ipv4_whitelist` | LPM_TRIE | `ipv4_trie_key{prefixlen, addr}` | `__u32` | 500,000 | IPv4 GeoIP whitelist (country code) |
| `events` | PERF_EVENT_ARRAY | int | int | 128 | Event reporting |
| `scratch` | PERCPU_ARRAY | `__u32` | `packet_info` | 1 | Per-CPU storage |

**Map Capacity Notes:**
- IPv4 List (250K): Supports IPSum (~230K rules) + manual rules + growth
- IPv4 CIDR Trie (10K): Supports Spamhaus (~1.5K rules) + other CIDR sources
- IPv6 maps (10K each): Reserved for future IPv6 threat intelligence
- Geo IPv4 Whitelist (500K): Supports GeoLite2-Country.mmdb (~500K+ networks)

**Value structure changed from `__u8` to `struct block_value` (16 bytes)** to support multi-source tracking.

To change map capacities, modify the constants in `ebpfs/xdp.bpf.c`:
```c
#define MAX_IPV4_LIST_ENTRIES 250000   // IPv4 精确匹配
#define MAX_IPV4_CIDR_ENTRIES 10000    // IPv4 CIDR
#define MAX_IPV6_LIST_ENTRIES 10000    // IPv6 精确匹配
#define MAX_IPV6_CIDR_ENTRIES 10000    // IPv6 CIDR
```

### Packet Processing Flow

#### XDP Program (`ebpfs/xdp.bpf.c`)

1. Parse Ethernet header → get protocol type
2. Handle VLAN tags (802.1Q/802.1AD) if present
3. Parse IPv4/IPv6 header with validation:
   - IPv4: Drop non-first fragments, validate header length
   - IPv6: Skip extension headers (max 8), drop fragment continuation
4. Match source IP against eBPF maps (exact match → CIDR match)
5. Return `XDP_DROP` if matched, `XDP_PASS` otherwise

**XDP filters at L2/L3 only** - does NOT parse transport layer (TCP/UDP).

## Common Development Commands

```bash
# Generate eBPF Go code from C source (required after changing .bpf.c)
make gen
# or: go generate ./internal/ebpfs

# Build the application
make build
# or: go build -o rho-aias

# Run (requires root/CAP_BPF for XDP)
make run
# or: sudo ./rho-aias

# Clean build artifacts
make clean

# Run packet generator tests
sudo python3 test/test_ipv4.py <target_ip> all
sudo python3 test/test_ipv6.py <target_ip> all

# Generate vmlinux.h (if missing/needs update)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h
```

## Code Generation (bpf2go)

The eBPF C code is compiled to Go using `cilium/ebpf/cmd/bpf2go`. This is configured in `internal/ebpfs/gen.go`:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ../../ebpfs/xdp.bpf.c -- -g -O2 -Wall
```

After modifying `ebpfs/xdp.bpf.c`, run `make gen` to regenerate:
- `internal/ebpfs/xdp_bpfel.go` (little-endian)
- `internal/ebpfs/xdp_bpfeb.go` (big-endian)
- `xdpObjects` struct with XDP program and maps

## Key Implementation Details

### XDP Attachment Modes

The program tries XDP attachment modes in order of performance:
1. **offload** - Best performance (NIC hardware acceleration)
2. **driver** - Good performance (driver-level)
3. **generic** - Fallback (kernel-level, lower performance)

See `internal/ebpfs/xdp.go:53-75`.

### IP Address Byte Encoding

**Critical:** For eBPF maps, IP addresses need specific byte ordering:

- **IPv4/IPv6 exact match:** Use raw bytes (network byte order)
- **CIDR match:** Use custom struct with prefix length in **little-endian** + IP address

From `utils/net.go:ParseValueToBytes`:
```go
// For IPv4 CIDR: [4 bytes prefixlen (LE) + 4 bytes IP]
binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
copy(bytes[4:], ipNet.IP.To4())

// For IPv6 CIDR: [4 bytes prefixlen (LE) + 16 bytes IP]
binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
copy(bytes[4:], ipNet.IP.To16())
```

This is because the LPM trie key's prefixlen field is stored in host byte order (x86 = little-endian).

### Perf Event Monitoring

The `MonitorEvents()` goroutine reads from the perf event buffer. Note: it has a **busy-wait issue** with the `default` case in the select statement that should be fixed - see `internal/ebpfs/xdp.go:99-129`.

## XDP Performance Optimizations

The XDP eBPF program has been optimized for performance with the following improvements:

### Branch Prediction Hints

Compiler hints for better CPU branch prediction:
```c
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
```

- `LIKELY(match_type == MATCH_BY_PASS)`: Most packets pass through
- `UNLIKELY(!pkt_info)`: Scratch map lookup rarely fails

### Reduced Memory Operations

**Before:** Every IPv6 match required `memset` + `memcpy` for entire structure
```c
// Old code - inefficient
struct in6_addr ipv6_addr;
__builtin_memset(&ipv6_addr, 0, sizeof(ipv6_addr));
__builtin_memcpy(&ipv6_addr, pi->src_ipv6, sizeof(ipv6_addr));
```

**After:** Only copy the necessary bytes
```c
// New code - efficient
struct in6_addr ipv6_addr;
__builtin_memcpy(&ipv6_addr.in6_u.u6_addr32, pi->src_ipv6, sizeof(ipv6_addr.in6_u.u6_addr32));
```

### IPv6 Extension Header Early Exit

**Optimization:** Skip the extension header loop when not needed (most common case)
```c
// Early exit for packets without extension headers
if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP ||
    nexthdr == 59 || nexthdr == IPPROTO_ICMPV6) {
    return 0;  // No extension headers, skip the loop
}
```

**Impact:** 5-15% performance improvement for IPv6 traffic (most IPv6 packets have no extension headers)

### Selective Field Initialization

**Before:** Full `memset` of 64-byte `packet_info` structure
```c
__builtin_memset(pkt_info, 0, sizeof(*pkt_info));
pkt_info->pkt_size = data_end - data;
```

**After:** Initialize only required fields
```c
pkt_info->eth_proto = 0;
pkt_info->src_ip = 0;
pkt_info->dst_ip = 0;
__builtin_memset(pkt_info->src_ipv6, 0, sizeof(pkt_info->src_ipv6));
__builtin_memset(pkt_info->dst_ipv6, 0, sizeof(pkt_info->dst_ipv6));
pkt_info->pkt_size = data_end - data;
pkt_info->match_type = 0;
```

### Performance Impact Summary

| Optimization | Expected Gain | Target Scenario |
|--------------|---------------|-----------------|
| Branch prediction hints | 2-5% | All packets |
| Reduced memset/memcpy | 5-10% | IPv6 packets |
| IPv6 early exit | 5-15% | IPv6 packets (most common) |
| Selective initialization | 1-3% | All packets |

**Overall expected improvement:** 5-15% for mixed traffic, up to 20% for IPv6-heavy workloads

### Code Location

All optimizations are implemented in `ebpfs/xdp.bpf.c`:
- Branch prediction macros: Line 35-37
- Optimized `match_by_rule()`: Line 158-190
- IPv6 early exit in `parse_ip_header()`: Line 277-282
- Optimized `xdp_prog()`: Line 348-411

## API Endpoints

All API endpoints follow RESTful convention: `/api/{module}/{action}`

### Manual Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/manual/rules` | List all rules with source information |
| POST | `/api/manual/rules` | Add filtering rule (sets MANUAL source bit) |
| DELETE | `/api/manual/rules` | Delete rule (removes MANUAL source bit) |

**Request format:**
```json
{
  "value": "192.168.1.1"        // IPv4, IPv6, CIDR, or MAC
}
```

**Response format (GET /api/manual/rules):**
```json
{
  "message": "GetRule",
  "data": {
    "rules": [
      {
        "key": "192.168.1.1",
        "sources": ["ipsum", "manual"],  // Which sources own this rule
        "value": {
          "source_mask": 5,              // 0x01 | 0x04 = 0x05
          "priority": 0,
          "expiry": 0
        }
      }
    ]
  }
}
```

### Threat Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/intel/status` | Get threat intel status with per-source statistics |
| POST | `/api/intel/update` | Manually trigger update for all enabled sources |

**Status response format:**
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
      "enabled": false,
      "last_update": "2024-01-14T02:00:00Z",
      "success": false,
      "rule_count": 0,
      "error": "source disabled"
    }
  }
}
```

**Note:** Next update time is not shown in the API response - each source's schedule is defined in `config.yml` using Cron expressions.

### Supported Rule Formats

- IPv4: `192.168.1.1`
- IPv4 CIDR: `192.168.1.0/24`
- IPv6: `2001:db8::1`
- IPv6 CIDR: `2001:db8::/32`
- MAC: `00:11:22:33:44:55`

**Note:** Wildcard matching uses CIDR notation (`0.0.0.0/0` or `::/0`), not plain `0.0.0.0`.

## Quick Testing Scripts

The `scripts/` directory provides shell scripts for quick manual rule testing:

### add.sh - Add Manual Rule

```bash
# Add a rule to block an IP
./scripts/add.sh

# Example: Blocks 192.168.110.138
curl --location --request POST 'http://192.168.110.139:8080/api/manual/rules' \
 --header 'Content-Type: application/json' \
 --data-raw '{
     "value": "192.168.110.138"
 }'
```

### del.sh - Delete Manual Rule

```bash
# Delete a rule
./scripts/del.sh

# Example: Removes 192.168.110.138 from blocklist
curl --location --request DELETE 'http://192.168.110.139:8080/api/manual/rules' \
 --header 'Content-Type: application/json' \
 --data-raw '{
     "value": "192.168.110.138"
 }'
```

### get.sh - List All Rules

```bash
# Get all current rules with source information
./scripts/get.sh

# Returns JSON with rules, sources, and bitmask info
curl 'http://192.168.110.139:8080/api/manual/rules' | jq
```

**Note:** These scripts use a hardcoded IP address (`192.168.110.139`). Modify them to match your server's address.

## Testing Tools

### IPv4 Testing (`test/test_ipv4.py`)

Generates IPv4 test packets using Scapy:

```bash
# Run all IPv4 tests
sudo python3 test/test_ipv4.py 192.168.1.1 all

# Specific tests
sudo python3 test/test_ipv4.py 192.168.1.1 ipv4_malformed_short_header
sudo python3 test/test_ipv4.py 192.168.1.1 ipv4_malformed_oversized --mtu 1492
```

Tests include:
- IPv4 malformed packets (short header, invalid protocol, bad version, etc.)
- IPv4 oversized packets (fragmentation testing)
- IPv4 zero-length packets

### IPv6 Testing (`test/test_ipv6.py`)

Generates IPv6 test packets using Scapy:

```bash
# Run all IPv6 tests
sudo python3 test/test_ipv6.py ::1 all

# Specific tests
sudo python3 test/test_ipv6.py ::1 ipv6_ext_hbh
sudo python3 test/test_ipv6.py ::1 ipv6_malformed_too_many_headers
```

Tests include:
- IPv6 normal packets (with/without extension headers)
- IPv6 malformed packets (too many headers, bad version, invalid fragment offset, etc.)
- IPv6 oversized packets

### Manual Testing with hping3

```bash
# IPv4 fragmentation tests
sudo hping3 -1 192.168.1.10 --data 1473 -c 1    # ICMP fragment
sudo hping3 -S 192.168.1.10 -p 80 --data 1473 -c 1  # TCP fragment

# IPv6 fragmentation test
sudo hping3 -6 -1 2001:db8::1 --data 1473
```

## Known Issues

1. **Busy-wait CPU usage** in XDP `MonitorEvents()` - the `default` case causes continuous looping
2. **MD5 used** in `utils/net.go` - should use SHA256 for security
3. **Multi-source rule deletion** - When disabling a threat intel source, rules owned by multiple sources are preserved (not bitwise deleted). See `internal/threatintel/sync.go:99-103` for TODO.

## Implementation Status

### Completed (Phase 1)
- ✅ eBPF `struct block_value` with source_mask tracking
- ✅ Go `BlockValue` type and bitmask helper functions
- ✅ Source-aware synchronization in threat intel module
- ✅ Manual rules set MANUAL bit (0x04)
- ✅ GetRule() returns source information
- ✅ **Per-source Cron scheduling** (robfig/cron/v3)
- ✅ **Optimized cache loading with LoadAll()** (skips GetRule() for empty kernel)
- ✅ **Expanded eBPF map capacities** (250K IPv4 rules, 10K CIDR rules)
- ✅ **Fixed deadlock in loadFromCache()** (non-reentrant lock issue)

### Completed (Phase 2 - Geo-Blocking)
- ✅ **Geo-blocking module** with fail-open safety
- ✅ **Delayed activation**: Only enables when data loaded successfully
- ✅ **eBPF geo maps**: `geo_config`, `geo_ipv4_whitelist` (500K entries)
- ✅ **MaxMind CSV/MMDB parser** with country filtering
- ✅ **IPv4 filter** for MMDB (excludes IPv6 networks)
- ✅ **Private network bypass** (RFC 1918) with `allow_private_networks`
- ✅ **Cache design fix**: Config items read from `config.yml`, not cache
- ✅ **Local persistence** for offline startup
- ✅ **File renaming**: `xdp.go` → `manual.go` (handles/routers)

### Completed (Phase 3 - Manual Rules & RESTful API)
- ✅ **Manual rule persistence** with gob binary format
- ✅ **Auto-load on startup** when `auto_load: true`
- ✅ **RESTful API routes**: `/api/{module}/{action}` structure
- ✅ **Manual routes**: `/api/manual/rules` (GET/POST/DELETE)
- ✅ **GeoBlocking routes**: `/api/geoblocking/*`
- ✅ **Intel routes**: `/api/intel/*` (unchanged)

### Planned (Phases 4-5)
- ⏳ Central coordinator for all source synchronization
- ⏳ API endpoints for source filtering (`GET /api/rule?source=manual`)
- ⏳ Per-source delete operations (`DELETE /api/rule?source=ipsum`)
- ⏳ Cache format migration (version 1 → 2)
- ⏳ Full bitwise delete implementation for multi-source rules

## Performance Notes

### Cache Loading Optimization

For 230K+ threat intelligence rules, cache loading has been optimized:

| Method | GetRule() | Diff Calculation | Load Time |
|--------|-----------|-----------------|-----------|
| `SyncToKernel()` | Yes (expensive) | Yes | Several seconds |
| `LoadAll()` | **No** | **No** | < 1 second |

**Usage:**
- `LoadAll()`: Used during `loadFromCache()` for startup/offline initialization
- `SyncToKernel()`: Used for scheduled updates and manual triggers

The `loadFromCache()` function is called within `Start()`'s mutex lock, so it directly updates status fields without calling `updateSourceStatus()` to avoid deadlock (Go mutexes are not reentrant).

## Graceful Shutdown

The application implements basic graceful shutdown:

- Captures SIGINT/SIGTERM signals
- HTTP server shuts down with 5-second timeout
- eBPF resources cleaned up via defer
- Threat intel manager stops scheduler

See `main.go:71-91` for implementation.

**Known limitation:** `MonitorEvents()` goroutine is not properly coordinated - it relies on channel closure but may have race conditions during shutdown.
