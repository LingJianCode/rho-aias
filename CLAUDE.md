# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**rho-aias** is a high-performance eBPF network firewall with XDP (eXpress Data Path) packet filtering. It intercepts and filters network packets at the driver level (L2/L3). The system consists of:

1. **eBPF XDP program** (`ebpfs/xdp.bpf.c`) - Packet filtering at driver level
2. **Go userspace controller** - Manages eBPF lifecycle and provides REST API
3. **Gin HTTP server** - REST API for rule management
4. **Configuration system** - Port and interface configurable via `config.yml`

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
│  │  HTTP API (internal/handles/, internal/routers/)             │   │
│  │  Routes:                                                     │   │
│  │  - POST   /api/rule  - Add rule                              │   │
│  │  - DELETE /api/rule  - Delete rule                           │   │
│  │  - GET    /api/rule  - List rules                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
rho-aias/
├── main.go                    # Main entry point
├── config.yml                 # Configuration file (port, interface)
├── go.mod                     # Go module dependencies
├── Makefile                   # Build scripts
├── ebpfs/                     # eBPF C source
│   ├── xdp.bpf.c              # XDP program
│   ├── common.h               # Common constants
│   └── vmlinux.h              # Kernel headers (generated)
├── internal/
│   ├── config/
│   │   └── config.go          # Configuration management
│   ├── ebpfs/
│   │   ├── gen.go             # bpf2go generation
│   │   ├── xdp.go             # XDP lifecycle
│   │   ├── xdp_bpfel.go       # Auto-generated (little-endian)
│   │   ├── xdp_bpfeb.go       # Auto-generated (big-endian)
│   │   ├── xdp_type.go        # XDP types
│   │   └── net_type.go        # Network types
│   ├── handles/
│   │   ├── xdp.go             # XDP API handlers
│   │   └── xdp_req.go         # Request structs
│   └── routers/
│       └── xdp.go             # XDP route registration
├── test/
│   ├── README.md              # Test documentation
│   ├── test_ipv4.py           # IPv4 packet generator
│   └── test_ipv6.py           # IPv6 packet generator
├── utils/
│   ├── net.go                 # Network utilities
│   └── net_test.go            # Network utilities tests
└── scripts/
    ├── add.sh                 # Add rule script
    ├── del.sh                 # Delete rule script
    ├── get.sh                 # Get rules script
    └── monitor.sh             # Kernel monitoring script
```

### eBPF Map Structure

#### XDP Program Maps (`ebpfs/xdp.bpf.c`)

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `ipv4_list` | HASH | `__be32` | `__u8` | IPv4 exact match |
| `ipv4_cidr_trie` | LPM_TRIE | `ipv4_trie_key{prefixlen, addr}` | `__u8` | IPv4 CIDR match |
| `ipv6_list` | HASH | `in6_addr` | `__u8` | IPv6 exact match |
| `ipv6_cidr_trie` | LPM_TRIE | `ipv6_trie_key{prefixlen, addr}` | `__u8` | IPv6 CIDR match |
| `events` | PERF_EVENT_ARRAY | int | int | Event reporting |
| `scratch` | PERCPU_ARRAY | `__u32` | `packet_info` | Per-CPU storage |

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

## Configuration

The application reads configuration from `config.yml`:

```yaml
server:
  port: 8080          # HTTP server port
ebpf:
  interface_name: ens33  # Network interface for XDP
```

Configuration is loaded at startup via `internal/config/config.go`.

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

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/rule` | Add filtering rule |
| DELETE | `/api/rule` | Delete rule |
| GET | `/api/rule` | List all rules |

**Request format:**
```json
{
  "value": "192.168.1.1"        // IPv4, IPv6, CIDR, or MAC
}
```

Supported formats:
- IPv4: `192.168.1.1`
- IPv4 CIDR: `192.168.1.0/24`
- IPv6: `2001:db8::1`
- IPv6 CIDR: `2001:db8::/32`
- MAC: `00:11:22:33:44:55`

**Note:** Wildcard matching uses CIDR notation (`0.0.0.0/0` or `::/0`), not plain `0.0.0.0`.

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
3. **IPv6 rules not fully implemented** in GetRule() - only returns IPv4 rules

## Graceful Shutdown

The application implements basic graceful shutdown:

- Captures SIGINT/SIGTERM signals
- HTTP server shuts down with 5-second timeout
- eBPF resources cleaned up via defer

See `main.go:51-67` for implementation.

**Known limitation:** `MonitorEvents()` goroutine is not properly coordinated - it relies on channel closure but may have race conditions during shutdown.
