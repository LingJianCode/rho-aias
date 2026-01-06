# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**rho-aias** is a dual-layer eBPF network firewall with both XDP (eXpress Data Path) and TC (Traffic Control) packet filtering. It uses eBPF programs to intercept and filter network packets at different points in the networking stack. The system consists of:

1. **eBPF XDP program** (`ebpfs/xdp.bpf.c`) - Early packet filtering at driver level
2. **eBPF TC program** (`ebpfs/tc.bpf.c`) - Layer 4 filtering (source IP + destination port)
3. **Go userspace controller** - Manages eBPF lifecycle and provides REST API
4. **Gin HTTP server** - REST API for rule management

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
│  │  TC Program (ebpfs/tc.bpf.c)                                 │   │
│  │  - TC ingress hook (after SKB allocation)                    │   │
│  │  - Filters by: source IP + destination port (L4)             │   │
│  │  - Maps: tc_rules (hash map with composite key)              │   │
│  │  - Returns: TC_ACT_SHOT or TC_ACT_OK                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Go Userspace (internal/ebpfs/)                              │   │
│  │  - xdp.go: XDP lifecycle and rule management                 │   │
│  │  - tc.go: TC lifecycle and rule management                   │   │
│  │  - Loaded via bpf2go from C sources                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  HTTP API (internal/handles/, internal/routers/)             │   │
│  │  XDP Routes:                                                 │   │
│  │  - POST   /api/rule  - Add XDP rule                          │   │
│  │  - DELETE /api/rule  - Delete XDP rule                       │   │
│  │  - GET    /api/rule  - List XDP rules                        │   │
│  │  TC Routes:                                                  │   │
│  │  - POST   /api/tc/rule    - Add TC rule                      │   │
│  │  - DELETE /api/tc/rule    - Delete TC rule                   │   │
│  │  - GET    /api/tc/rules   - List TC rules                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### eBPF Map Structure

#### XDP Program Maps (`ebpfs/xdp.bpf.c`)

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `ipv4_list` | HASH | `__be32` | `__u8` | IPv4 exact match |
| `ipv4_cidr_trie` | LPM_TRIE | `ipv4_trie_key{prefixlen, addr}` | `__u8` | IPv4 CIDR match |
| `ipv6_list` | HASH | `in6_addr` | `__u8` | IPv6 exact match |
| `ipv6_cidr_trie` | LPM_TRIE | `ipv6_trie_key{prefixlen, addr}` | `__u8` | IPv6 CIDR match |
| `events` | PERF_EVENT_ARRAY | int | int | Send matched packets to userspace |
| `scratch` | PERCPU_ARRAY | `__u32` | `packet_info` | Per-CPU temporary storage |

#### TC Program Maps (`ebpfs/tc.bpf.c`)

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `tc_rules` | HASH | `tc_rule_key{src_ip, dst_port, proto}` | `__u8` | L4 filtering (src IP + dst port) |

**TC Map Key Structure:**
```c
struct tc_rule_key {
    __u32 src_ip;      // Source IPv4 (host byte order, 0 = wildcard)
    __u16 dst_port;    // Destination port (host byte order)
    __u16 proto;       // Protocol (IPPROTO_TCP=6, IPPROTO_UDP=17)
    __u16 padding;     // 8-byte alignment
};
```

**Wildcard behavior:** `src_ip = 0.0.0.0` matches ANY source IP for the given port/protocol.

### Packet Processing Flow

#### XDP Program (`ebpfs/xdp.bpf.c`)

1. Parse Ethernet header → get protocol type
2. Handle VLAN tags (802.1Q/802.1AD) if present
3. Parse IPv4/IPv6 header with validation:
   - IPv4: Drop non-first fragments, validate header length
   - IPv6: Skip extension headers (max 8), drop fragment continuation
4. Match source IP against eBPF maps (exact match → CIDR match)
5. Report matched packets via perf event buffer
6. Return `XDP_DROP` if matched, `XDP_PASS` otherwise

**XDP filters at L2/L3 only** - does NOT parse transport layer (TCP/UDP).

#### TC Program (`ebpfs/tc.bpf.c`)

1. Parse Ethernet header → get protocol type
2. Handle VLAN tags (802.1Q/802.1AD) if present
3. Parse IPv4 header (IPv6 not supported in TC)
4. Parse TCP/UDP header to get destination port
5. Match against `tc_rules` map:
   - First try exact match: `{src_ip, dst_port, proto}`
   - Then try wildcard match: `{src_ip=0, dst_port, proto}`
6. Return `TC_ACT_SHOT` if matched, `TC_ACT_OK` otherwise

**TC filters at L4** - parses transport layer (TCP/UDP) for port-based filtering.

## Common Development Commands

```bash
# Generate eBPF Go code from C source (required after changing xdp.bpf.c)
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
make test
# or: python3 test/packet_generator.py <target_ip> all

# Generate vmlinux.h (if missing/needs update)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h
```

## Code Generation (bpf2go)

The eBPF C code is compiled to Go using `cilium/ebpf/cmd/bpf2go`. This is configured in `internal/ebpfs/gen.go`:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ../../ebpfs/xdp.bpf.c -- -g -O2 -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tc ../../ebpfs/tc.bpf.c -- -g -O2 -Wall
```

After modifying `ebpfs/xdp.bpf.c` or `ebpfs/tc.bpf.c`, run `make gen` to regenerate:

**XDP generates:**
- `internal/ebpfs/xdp_bpfel.go` (little-endian)
- `internal/ebpfs/xdp_bpfeb.go` (big-endian)
- `xdpObjects` struct with XDP program and maps

**TC generates:**
- `internal/ebpfs/tc_bpfel.go` (little-endian)
- `internal/ebpfs/tc_bpfeb.go` (big-endian)
- `tcObjects` struct with TC program and maps

## Key Implementation Details

### XDP Attachment Modes

The program tries XDP attachment modes in order of performance:
1. **offload** - Best performance (NIC hardware acceleration)
2. **driver** - Good performance (driver-level)
3. **generic** - Fallback (kernel-level, lower performance)

See `internal/ebpfs/xdp.go:54-75`.

### TC Attachment

The TC program attaches to the **ingress** hook using the TCX API (kernel 6.6+):
- Uses `link.AttachTCX()` with `ebpf.AttachTCXIngress`
- Falls back to netlink attachment if TCX is unavailable
- Requires root privileges or CAP_BPF capability

See `internal/ebpfs/tc.go:48-65`.

### IP Address Byte Encoding

**Critical:** For eBPF maps, IP addresses need specific byte ordering:

- **IPv4/IPv6 exact match:** Use raw bytes (network byte order)
- **CIDR match:** Use custom struct with prefix length in **little-endian** + IP address

From `utils/net.go:ParseValueToBytes`:
```go
// For IPv4 CIDR: [4 bytes prefixlen (LE) + 4 bytes IP]
binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
copy(bytes[4:], ipNet.IP.To4())
```

This is because the LPM trie key's prefixlen field is stored in host byte order (x86 = little-endian).

### Perf Event Monitoring

The `MonitorEvents()` goroutine reads from the perf event buffer. Note: it has a **busy-wait issue** with the `default` case in the select statement that should be fixed - see `internal/ebpfs/xdp.go:99-128`.

## API Endpoints

### XDP Rules (L2/L3 Filtering)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/rule` | Add XDP filtering rule |
| DELETE | `/api/rule` | Delete XDP rule |
| GET | `/api/rule` | List all XDP rules |

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

### TC Rules (L4 Filtering)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/tc/rule` | Add TC filtering rule |
| DELETE | `/api/tc/rule` | Delete TC rule |
| GET | `/api/tc/rules` | List all TC rules |

**Request format:**
```json
{
  "src_ip": "192.168.1.100",   // Source IP (0.0.0.0 = wildcard)
  "dst_port": 80,               // Destination port
  "proto": "tcp"                // Protocol: "tcp" or "udp"
}
```

**Wildcard examples:**
```json
// Block ALL traffic to port 80 (any source IP)
{
  "src_ip": "0.0.0.0",
  "dst_port": 80,
  "proto": "tcp"
}

// Block all traffic from specific IP to port 443
{
  "src_ip": "10.0.0.5",
  "dst_port": 443,
  "proto": "tcp"
}
```

## Known Issues

1. **Busy-wait CPU usage** in XDP `MonitorEvents()` - the `default` case causes continuous looping
2. **Hardcoded interface** "ens33" in `main.go:13`
3. **No graceful shutdown** - missing signal handling for SIGTERM/SIGINT
4. **MD5 used** in `utils/net.go` - should use SHA256 for security
5. **TC IPv6 support** - TC filter only supports IPv4, not IPv6
