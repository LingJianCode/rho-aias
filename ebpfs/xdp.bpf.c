//go:build ignore

/* XDP (eXpress Data Path) BPF 程序
 *
 * 功能:
 * - 在网络驱动层拦截和处理数据包，性能优于传统 netfilter/iptables
 * - 根据 IPv4 地址或 CIDR 规则过滤数据包
 * - 将匹配的数据包事件发送到用户空间监控
 *
 * 数据包处理流程:
 * 1. 解析以太网头 -> 获取协议类型
 * 2. 处理 VLAN 标签 (如果存在)
 * 3. 解析 IPv4 头部
 *    - 验证头部完整性
 *    - 处理 IP 分片 (只处理首片)
 * 4. 根据规则匹配 IP 地址
 * 5. 将事件上报到用户空间
 * 6. 返回 XDP_DROP 或 XDP_PASS
 *
 * 安全特性:
 * - IPv4 分片: 只处理首片 (offset=0)，丢弃后续分片
 * - 边界检查: 所有指针访问前都进行边界验证
 */

#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Branch prediction optimization macros
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

// Rule match types
#define MATCH_BY_PASS      0     // No rule matched
#define MATCH_BY_IP4_EXACT  1    // Match IPv4 address exactly
#define MATCH_BY_IP4_CIDR   2    // Match IPv4 address by CIDR block
#define MATCH_BY_GEO_BLOCK  6    // Match by geo-blocking rule
#define MATCH_BY_WHITELIST  7    // Match by IP whitelist (pass directly)

// Feature flags for skipping empty map lookups (优化: 空 map 快速跳过)
#define FEATURE_WHITELIST   (1 << 0)  // whitelist maps have entries
#define FEATURE_BLACKLIST   (1 << 1)  // blacklist maps have entries

// Maximum number of entries in whitelist maps
#define MAX_WHITELIST_IPV4_LIST_ENTRIES 10000    // IPv4 whitelist exact match
#define MAX_WHITELIST_IPV4_CIDR_ENTRIES 5000     // IPv4 whitelist CIDR

// Maximum number of entries in each map
// 威胁情报数据量: IPSum ~230K, Spamhaus ~1.5K
#define MAX_IPV4_LIST_ENTRIES 250000   // IPv4 精确匹配（IPSum 有 23万+）
#define MAX_IPV4_CIDR_ENTRIES 10000    // IPv4 CIDR（Spamhaus 1,454 + 预留）

// Default prefix lengths for IP lookups
#define DEFAULT_IPV4_PREFIX  32  // Full IPv4 address length for LPM lookup
#define DEFAULT_KEY 0

/* Packet information structure for processing and event reporting
 * 总大小: 22 bytes, packed 避免填充
 * 包含传输层协议信息、TCP 标志位和目标端口
 */
struct packet_info {
    // Network layer - IPv4 addresses (8 bytes)
    __be32 src_ip;                  // 源 IPv4 地址
    __be32 dst_ip;                  // 目的 IPv4 地址

    // Protocol information (4 bytes)
    __u16 eth_proto;                // 以太网协议类型 (ETH_P_IP)
    __u8 ip_protocol;               // IP 协议类型 (TCP=6, UDP=17, ICMP=1)
    __u8 tcp_flags;                 // TCP 标志位 (SYN=0x02, ACK=0x10, etc.)

    // Transport layer (2 bytes)
    __be16 dst_port;                // 目标端口 (TCP/UDP, 网络字节序)

    // Metadata (8 bytes)
    __u32 pkt_size;                 // 数据包总大小
    __u32 match_type;               // 匹配的规则类型
} __attribute__((packed));          // 22 bytes

/* eBPF maps definitions
 * All maps are limited to MAX_ENTRIES_SIZE entries
 */

// IPv4 exact match hash table
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct block_value);
    __uint(max_entries, MAX_IPV4_LIST_ENTRIES);
} block_ipv4_list SEC(".maps");

/* LPM (Longest Prefix Match) Trie key for IPv4 CIDR matching
 * Used with BPF_MAP_TYPE_LPM_TRIE map
 */
struct ipv4_trie_key {
    __u32 prefixlen;        // CIDR prefix length
    __be32 addr;            // IPv4 address
};

// IPv4 CIDR LPM trie
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_trie_key);
    __type(value, struct block_value);
    __uint(max_entries, MAX_IPV4_CIDR_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} block_ipv4_cidr_trie SEC(".maps");

// Scratch map for storing packet information
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct packet_info);
    __uint(max_entries, 1);
} scratch SEC(".maps");

// Ring buffer for reporting matched packets (Linux 5.8+)
// BPF_MAP_TYPE_RINGBUF offers better performance than PERF_EVENT_ARRAY:
// - Global shared buffer instead of per-CPU buffers
// - Guaranteed event ordering
// - Lower memory overhead and fewer wakeups
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1MB buffer size
} events SEC(".maps");

// Geo-blocking configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct geo_config);
    __uint(max_entries, 1);
} geo_config SEC(".maps");

// Geo-blocking state structure
struct geo_config {
    __u32 enabled;        /* Geo-blocking enabled flag */
    __u32 mode;           /* 0: whitelist, 1: blacklist */
    __u32 padding;        /* Alignment padding */
} __attribute__((packed));

// Event reporting configuration map
// Controls whether to report dropped packet events to userspace
struct event_config {
    __u32 enabled;        /* Event reporting enabled flag (0=disabled, 1=enabled) */
    __u32 sample_rate;    /* Sample rate: report 1 out of every N dropped packets (e.g., 1000 = 0.1%) */
    __u32 padding[2];     /* Alignment padding to 16 bytes */
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct event_config);
    __uint(max_entries, 1);
} event_config SEC(".maps");

// Anomaly detection configuration map
// Controls whether to sample packets for anomaly detection
struct anomaly_config {
    __u32 enabled;            /* Anomaly detection enabled flag (0=disabled, 1=enabled) */
    __u32 sample_rate;        /* Sample rate: report 1 out of every N packets (e.g., 100 = 1%) */
    __u32 port_filter_enabled; /* Port filter enabled flag (0=monitor all ports, 1=only monitored ports) */
    __u32 padding;            /* Alignment padding */
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct anomaly_config);
    __uint(max_entries, 1);
} anomaly_config SEC(".maps");

// Ring buffer for anomaly detection sampling
// Samples all passing packets (not blocked) for statistical analysis
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1MB buffer size
} anomaly_events SEC(".maps");

// Anomaly detection port filter map
// Key: port number (host byte order), Value: flag (1 = monitored)
// Only packets destined to these ports will be sampled for anomaly detection
// (when port_filter_enabled is set in anomaly_config)
// 使用 ARRAY 替代 HASH: 端口直接作为数组下标，O(1) 查找无哈希开销
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 65536);  // port range 0-65535
} anomaly_ports SEC(".maps");

// Feature flags bitmap for skipping empty map lookups
// 由用户空间在规则增删时更新，避免对空 map 做无用 lookup
// Bit 0: whitelist maps have entries
// Bit 1: blacklist maps have entries
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} feature_flags SEC(".maps");

// IPv4 GeoIP whitelist LPM trie
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_trie_key);
    __type(value, __u32);  /* Country code as value */
    __uint(max_entries, 500000);  /* GeoLite2-Country.mmdb has ~500K+ networks */
    __uint(map_flags, BPF_F_NO_PREALLOC);
} geo_ipv4_whitelist SEC(".maps");

// ============================================
// IP Whitelist eBPF Maps
// 白名单优先级最高：命中白名单直接 XDP_PASS，跳过所有后续检查
// ============================================

// IPv4 whitelist exact match hash table
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct block_value);
    __uint(max_entries, MAX_WHITELIST_IPV4_LIST_ENTRIES);
} whitelist_ipv4_list SEC(".maps");

// IPv4 whitelist CIDR LPM trie
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_trie_key);
    __type(value, struct block_value);
    __uint(max_entries, MAX_WHITELIST_IPV4_CIDR_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_ipv4_cidr_trie SEC(".maps");

// ============================================
// Transport layer parsing helper functions
// ============================================

// Protocol type constants
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_ICMP 1

// TCP flag bit masks
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

/* 解析传输层头部
 * @pkt_info: 数据包信息结构体
 * @ip_data: IP 头部起始位置
 * @iph_len: IP 头部长度
 * @data_end: 数据包结束指针
 * @protocol: IP 协议号
 *
 * 填充 pkt_info->ip_protocol, pkt_info->tcp_flags 和 pkt_info->dst_port
 */
static __always_inline void parse_transport_layer(
    struct packet_info *pkt_info,
    void *ip_data,
    __u32 iph_len,
    void *data_end,
    __u8 protocol)
{
    pkt_info->ip_protocol = protocol;
    pkt_info->tcp_flags = 0;
    pkt_info->dst_port = 0;

    // 只解析 TCP 的标志位和端口
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(ip_data + iph_len);

        // 验证 TCP 头边界（至少 20 字节）
        if ((void *)(tcph + 1) > data_end)
            return;

        // 使用 bpf_core_read 安全读取，避免 eBPF 验证器拒绝直接内存访问
        struct tcphdr tcp_hdr;
        if (bpf_core_read(&tcp_hdr, sizeof(tcp_hdr), tcph) == 0) {
            // 从位域构建标志位
            __u8 flags = 0;
            if (tcp_hdr.fin) flags |= 0x01;
            if (tcp_hdr.syn) flags |= 0x02;
            if (tcp_hdr.rst) flags |= 0x04;
            if (tcp_hdr.psh) flags |= 0x08;
            if (tcp_hdr.ack) flags |= 0x10;
            if (tcp_hdr.urg) flags |= 0x20;
            if (tcp_hdr.ece) flags |= 0x40;
            if (tcp_hdr.cwr) flags |= 0x80;
            pkt_info->tcp_flags = flags;
            pkt_info->dst_port = tcp_hdr.dest;
        }
    } else if (protocol == IPPROTO_UDP) {
        // 解析 UDP 目标端口
        struct udphdr *udph = (struct udphdr *)(ip_data + iph_len);

        // 验证 UDP 头边界（至少 8 字节）
        if ((void *)(udph + 1) > data_end)
            return;

        // 使用 bpf_core_read 安全读取
        struct udphdr udp_hdr;
        if (bpf_core_read(&udp_hdr, sizeof(udp_hdr), udph) == 0) {
            pkt_info->dst_port = udp_hdr.dest;
        }
    }
    // ICMP 不需要特殊处理，只需要记录协议类型
}

/* 检查数据包是否匹配 IP 白名单规则
 * @pi: 包含已解析数据包信息的结构体
 * 返回值: 1=命中白名单(应放行), 0=未命中
 *
 * 白名单优先级最高：命中白名单的数据包直接 XDP_PASS，
 * 跳过后续的 geo-blocking 和黑名单检查
 */
static __always_inline int check_whitelist(struct packet_info *pi) {
    // 快速跳过: 白名单为空时无需查询
    __u32 flags_key = 0;
    __u32 *flags = bpf_map_lookup_elem(&feature_flags, &flags_key);
    if (!flags || !(*flags & FEATURE_WHITELIST))
        return 0;

    // IPv4 白名单检查
    if (pi->eth_proto == ETH_P_IP) {
        // 精确匹配
        struct block_value *val = bpf_map_lookup_elem(&whitelist_ipv4_list, &pi->src_ip);
        if (val && val->source_mask != 0) return 1;

        // CIDR 匹配
        struct ipv4_trie_key v4_key = {
            .prefixlen = DEFAULT_IPV4_PREFIX,
            .addr = pi->src_ip
        };
        val = bpf_map_lookup_elem(&whitelist_ipv4_cidr_trie, &v4_key);
        if (val && val->source_mask != 0) return 1;
    }

    return 0; // 未命中白名单
}

/* 检查数据包是否匹配地域封禁规则
 * @pi: 包含已解析数据包信息的结构体
 * 返回值: 1=通过, 0=阻断
 *
 * TCP 连接状态感知:
 * - 只对纯 SYN 包（新建连接）做地域检查
 * - 对已建立连接的响应包（SYN-ACK/ACK/PSH 等）直接放行
 * - 这样本机主动向国外服务器发起的请求，其响应包不会被误拦截
 *
 * 原理:
 * - 外部主动连入: 第一个包是纯 SYN → 做地域检查
 * - 本机主动连出: 本机发 SYN(egress 不可见), 服务器回 SYN-ACK(含 ACK 位) → 放行
 * - 后续数据包: 含 ACK 位 → 放行
 *
 * 注意: 此机制仅对 TCP 有效，UDP/ICMP 仍按原逻辑处理
 */
static __always_inline int check_geo_blocking(struct packet_info *pi) {
    __u32 key = 0;
    struct geo_config *config = bpf_map_lookup_elem(&geo_config, &key);

    // Early exit if geo-blocking disabled
    if (UNLIKELY(!config || !config->enabled))
        return 1;  // Pass

    // Only process IPv4 packets
    if (pi->eth_proto == ETH_P_IP) {
        // TCP 连接状态感知: 非纯 SYN 包放行（已建立连接的响应包）
        // 纯 SYN = SYN=1 && ACK=0: 新建连接请求，需要做地域检查
        // SYN-ACK = SYN=1 && ACK=1: 服务器响应本机连接，放行
        // ACK/PSH-ACK 等: 已建立连接的数据传输，放行
        if (pi->ip_protocol == IPPROTO_TCP) {
            if (!(pi->tcp_flags & TCP_FLAG_SYN) || (pi->tcp_flags & TCP_FLAG_ACK)) {
                return 1;  // 非新建连接，放行
            }
        }

        // Check IPv4 against whitelist
        struct ipv4_trie_key v4_key = {
            .prefixlen = DEFAULT_IPV4_PREFIX,
            .addr = pi->src_ip
        };
        __u32 *country = bpf_map_lookup_elem(&geo_ipv4_whitelist, &v4_key);

        if (config->mode == 0) {  // Whitelist mode
            // Block if country not found
            return (country != NULL);
        } else {  // Blacklist mode
            // Block if country found
            return (country == NULL);
        }
    }

    // Pass for non-IPv4 packets
    return 1;
}

/* 检查数据包是否匹配配置的过滤规则
 * @pi: 包含已解析数据包信息的结构体
 * 返回值: 匹配类型 (MATCH_BY_IP4_EXACT/IP4_CIDR) 或 MATCH_BY_PASS
 *
 * 匹配顺序: IPv4 精确匹配 -> IPv4 CIDR 匹配
 */
static __always_inline __u32 match_by_rule(struct packet_info *pi) {
    // 快速跳过: 黑名单为空时无需查询
    __u32 flags_key = 0;
    __u32 *flags = bpf_map_lookup_elem(&feature_flags, &flags_key);
    if (!flags || !(*flags & FEATURE_BLACKLIST))
        return MATCH_BY_PASS;

    // ETH_P_IP 宏定义的是 网络字节序的值, pi->eth_proto 从数据包中读出的也是 网络字节序
    // reference: https://docs.kernel.org/next/bpf/map_lpm_trie.html#bpf-map-lookup-elem
    // Process IPv4 packets
    if (pi->eth_proto == ETH_P_IP) {
        // Try exact match first
        struct block_value *ipv4_value = bpf_map_lookup_elem(&block_ipv4_list, &pi->src_ip);
        if (ipv4_value && ipv4_value->source_mask != 0) return MATCH_BY_IP4_EXACT;

        // Then try CIDR match using LPM Trie
        struct ipv4_trie_key v4_key = {
            .prefixlen = DEFAULT_IPV4_PREFIX,
            .addr = pi->src_ip
        };
        struct block_value *ipv4_cidr_value = bpf_map_lookup_elem(&block_ipv4_cidr_trie, &v4_key);
        if (ipv4_cidr_value && ipv4_cidr_value->source_mask != 0) return MATCH_BY_IP4_CIDR;
    }
    return MATCH_BY_PASS;
}

/* 解析 IP 层头部信息
 * @pkt_info: 输出参数，填充解析后的数据包信息
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * 返回值: 0=成功, 1=数据包异常(应丢弃), 2=非 IP 协议, -1=数据包过短(应放行)
 *
 * 处理流程:
 * 1. 解析以太网头
 * 2. 处理 VLAN 标签 (802.1Q/802.1AD)
 * 3. 解析 IPv4 头部
 */
static __always_inline int parse_ip_header(struct packet_info *pkt_info, void *data, void *data_end) {

    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    pkt_info->eth_proto = bpf_ntohs(eth->h_proto);
    
    void *ip_data = (void *)(eth + 1);
    
    // 处理 VLAN 标签
    if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return -1;
        ip_data = (void *)(vlan + 1);
        pkt_info->eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
    }
    
    // 只处理 IPv4 数据包
    if (pkt_info->eth_proto == ETH_P_IP) {
        // IPv4 处理
        struct iphdr *iph = (struct iphdr *)ip_data;

        // 验证基本 IP 头边界
        if ((void *)(iph + 1) > data_end)
            return 1;

        // 验证 IP 头长度 (ihl 以 4 字节为单位，最小 5)
        // 同时检查整数乘法后是否溢出数据包边界
        if (iph->ihl < 5 || iph->ihl > 15)
            return 1;
        __u32 iph_len = iph->ihl * 4;
        if ((void *)iph + iph_len > data_end)
            return 1;

        // 验证协议类型 (确保是已知协议)
        if (iph->protocol == 0 || iph->protocol > 255)
            return 1;

        // IPv4 分片处理: 只处理首片分片
        if (iph->frag_off & bpf_htons(IP_OFFSET))
            return 1;

        // 填充 IPv4 地址信息
        pkt_info->src_ip = iph->saddr;
        pkt_info->dst_ip = iph->daddr;
        pkt_info->ip_protocol = iph->protocol;
        pkt_info->tcp_flags = 0;

        // 解析传输层（TCP 标志位）
        parse_transport_layer(pkt_info, ip_data, iph_len, data_end, iph->protocol);
        
        return 0;
    }
    
    return 2; // 非 IPv4 协议
}

/* XDP 程序主入口点
 * @ctx: XDP 元数据结构，包含数据包指针和接口信息
 * 返回值: XDP_DROP (丢弃) 或 XDP_PASS (放行)
 *
 * 处理流程:
 * 1. 从 scratch map 获取临时存储空间
 * 2. 解析数据包头部信息
 * 3. 根据规则匹配决定是否丢弃
 * 4. 将匹配事件上报到用户空间
 */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct packet_info *pkt_info;
    __u32 key = DEFAULT_KEY;
    __u32 match_type = DEFAULT_KEY;

    // 基本边界检查
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    // 从 scratch map 获取 percpu 存储空间
    pkt_info = bpf_map_lookup_elem(&scratch, &key);
    if (UNLIKELY(!pkt_info)) {
        bpf_printk("Failed to lookup scratch map\n");
        return XDP_PASS;
    }

    // 只初始化 parse_ip_header 不会覆盖的字段
    // eth_proto/src_ip/dst_ip/ip_protocol/tcp_flags/dst_port
    // 均由 parse_ip_header 在各分支中设置，无需预先清零
    pkt_info->pkt_size = data_end - data;
    pkt_info->match_type = 0;

    int res = parse_ip_header(pkt_info, data, data_end);
    switch (res) {
        case 0:
            // 解析成功，继续处理
            goto submit;
        case 1:
            // 数据包异常 (分片后续片/头部损坏)
            return XDP_DROP;
        case 2:
            // 非 IP 协议，放行
            return XDP_PASS;
        default:
            return XDP_PASS;
    }

submit:
    // IP whitelist check (highest priority - skip all other checks)
    {
        int whitelist_result = check_whitelist(pkt_info);
        if (UNLIKELY(whitelist_result)) {
            pkt_info->match_type = MATCH_BY_WHITELIST;
            return XDP_PASS;
        }
    }

    // Geo-blocking check (before rule matching for early drop)
    {
        int geo_result = check_geo_blocking(pkt_info);
        if (UNLIKELY(!geo_result)) {
            pkt_info->match_type = MATCH_BY_GEO_BLOCK;
            return XDP_DROP;
        }
    }

    // 检查是否匹配过滤规则
    match_type = match_by_rule(pkt_info);
    pkt_info->match_type = match_type;

    // 分支预测优化: 大多数包会通过，使用 LIKELY 提示编译器
    if (LIKELY(match_type == MATCH_BY_PASS)) {
        // 异常检测采样：对通过的数据包进行采样上报（用于统计检测）
        {
            __u32 config_key = 0;
            struct anomaly_config *cfg = bpf_map_lookup_elem(&anomaly_config, &config_key);
            
            // 只有在配置启用时才上报采样事件
            if (cfg && cfg->enabled) {
                __u32 sample_rate = cfg->sample_rate;
                if (sample_rate == 0) {
                    sample_rate = 100; // 默认采样率 1%
                }
                
                // 采样逻辑：random % sample_rate == 0 则上报
                __u32 random_val = bpf_get_prandom_u32();
                if ((random_val % sample_rate) == 0) {
                        // 端口过滤检查：如果启用了端口过滤，只上报匹配端口的数据包
                        // 但是 ICMP 没有端口，应该始终上报用于 Flood 检测
                        int pass_port_check = 1;
                        if (cfg->port_filter_enabled) {
                            // ICMP (1) 绕过端口过滤
                            if (pkt_info->ip_protocol != IPPROTO_ICMP) {
                                __u32 port_key = bpf_ntohs(pkt_info->dst_port);
                                __u32 *port_val = bpf_map_lookup_elem(&anomaly_ports, &port_key);
                                // ARRAY map: 未设置的端口值为 0
                                if (!port_val || *port_val == 0) {
                                    pass_port_check = 0;
                                }
                            }
                        }

                    if (pass_port_check) {
                        // 上报到 anomaly_events ring buffer
                        bpf_ringbuf_output(&anomaly_events, pkt_info, sizeof(*pkt_info), 0);
                    }
                }
            }
        }
        return XDP_PASS;
    }

    // 匹配规则则丢弃，并根据配置决定是否上报事件
    {
        __u32 config_key = 0;
        struct event_config *cfg = bpf_map_lookup_elem(&event_config, &config_key);
        
        // 只有在配置启用时才上报事件
        if (cfg && cfg->enabled) {
            // 采样逻辑：使用随机数决定是否上报
            // sample_rate = N 表示每 N 个丢弃包上报 1 个
            // 例如：sample_rate = 1000 表示 0.1% 的上报率
            __u32 sample_rate = cfg->sample_rate;
            if (sample_rate == 0) {
                sample_rate = 1000; // 默认采样率，防止除零
            }
            
            // bpf_get_prandom_u32() 返回 0 到 UINT32_MAX 之间的随机数
            // 如果 random % sample_rate == 0，则上报
            __u32 random_val = bpf_get_prandom_u32();
            if ((random_val % sample_rate) == 0) {
                bpf_ringbuf_output(&events, pkt_info, sizeof(*pkt_info), 0);
            }
        }
    }
    
    return XDP_DROP;
}