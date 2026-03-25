//go:build ignore

/* XDP (eXpress Data Path) BPF 程序
 *
 * 功能:
 * - 在网络驱动层拦截和处理数据包，性能优于传统 netfilter/iptables
 * - 根据 IPv4/IPv6 地址或 CIDR 规则过滤数据包
 * - 将匹配的数据包事件发送到用户空间监控
 *
 * 数据包处理流程:
 * 1. 解析以太网头 -> 获取协议类型
 * 2. 处理 VLAN 标签 (如果存在)
 * 3. 解析 IP 层 (IPv4/IPv6)
 *    - 验证头部完整性
 *    - 处理 IP 分片 (只处理首片)
 *    - 处理 IPv6 扩展头链
 * 4. 根据规则匹配 IP 地址
 * 5. 将事件上报到用户空间
 * 6. 返回 XDP_DROP 或 XDP_PASS
 *
 * 安全特性:
 * - IPv4 分片: 只处理首片 (offset=0)，丢弃后续分片
 * - IPv6 扩展头: 限制扩展头数量 (最多 8 个)
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
#define MATCH_BY_IP6_EXACT  3    // Match IPv6 address exactly
#define MATCH_BY_IP6_CIDR   4    // Match IPv6 address by CIDR block
#define MATCH_BY_MAC        5    // Match MAC address exactly
#define MATCH_BY_GEO_BLOCK  6    // Match by geo-blocking rule
#define MATCH_BY_WHITELIST  7    // Match by IP whitelist (pass directly)

// Maximum number of entries in whitelist maps
#define MAX_WHITELIST_IPV4_LIST_ENTRIES 10000    // IPv4 whitelist exact match
#define MAX_WHITELIST_IPV4_CIDR_ENTRIES 5000     // IPv4 whitelist CIDR
#define MAX_WHITELIST_IPV6_LIST_ENTRIES 10000    // IPv6 whitelist exact match
#define MAX_WHITELIST_IPV6_CIDR_ENTRIES 5000     // IPv6 whitelist CIDR

// Maximum number of entries in each map
// 威胁情报数据量: IPSum ~230K, Spamhaus ~1.5K
#define MAX_IPV4_LIST_ENTRIES 250000   // IPv4 精确匹配（IPSum 有 23万+）
#define MAX_IPV4_CIDR_ENTRIES 10000    // IPv4 CIDR（Spamhaus 1,454 + 预留）
#define MAX_IPV6_LIST_ENTRIES 10000    // IPv6 精确匹配（预留）
#define MAX_IPV6_CIDR_ENTRIES 10000    // IPv6 CIDR（预留）

// Default prefix lengths for IP lookups
#define DEFAULT_IPV6_PREFIX  128 // Full IPv6 address length for LPM lookup
#define DEFAULT_IPV4_PREFIX  32  // Full IPv4 address length for LPM lookup
#define DEFAULT_KEY 0

// IPv6 extension header limits (防止 DoS 攻击)
#define MAX_IPV6_EXT_HEADERS 8   // 最多处理的扩展头数量

/* Packet information structure for processing and event reporting
 * 总大小: 64 bytes, packed 避免填充
 * 包含传输层协议信息和 TCP 标志位
 */
struct packet_info {
    // Network layer - IPv4 addresses (8 bytes)
    __be32 src_ip;                  // 源 IPv4 地址
    __be32 dst_ip;                  // 目的 IPv4 地址

    // Network layer - IPv6 addresses (32 bytes)
    __be32 src_ipv6[4];             // 源 IPv6 地址 (128 bits)
    __be32 dst_ipv6[4];             // 目的 IPv6 地址 (128 bits)

    // Protocol information (4 bytes)
    __u16 eth_proto;                // 以太网协议类型 (ETH_P_IP/ETH_P_IPV6)
    __u8 ip_protocol;               // IP 协议类型 (TCP=6, UDP=17, ICMP=1)
    __u8 tcp_flags;                 // TCP 标志位 (SYN=0x02, ACK=0x10, etc.)

    // Metadata (8 bytes)
    __u32 pkt_size;                 // 数据包总大小
    __u32 match_type;               // 匹配的规则类型
} __attribute__((packed));          // 64 bytes

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

// IPv6 exact match hash table
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, struct block_value);
    __uint(max_entries, MAX_IPV6_LIST_ENTRIES);
} block_ipv6_list SEC(".maps");

/* LPM (Longest Prefix Match) Trie key for IPv6 CIDR matching
 * Used with BPF_MAP_TYPE_LPM_TRIE map
 */
struct ipv6_trie_key {
    __u32 prefixlen;        // CIDR prefix length
    struct in6_addr addr;    // IPv6 address
};

// IPv6 CIDR LPM trie
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_trie_key);
    __type(value, struct block_value);
    __uint(max_entries, MAX_IPV6_CIDR_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} block_ipv6_cidr_trie SEC(".maps");

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
    __u32 enabled;        /* Anomaly detection enabled flag (0=disabled, 1=enabled) */
    __u32 sample_rate;    /* Sample rate: report 1 out of every N packets (e.g., 100 = 1%) */
    __u32 padding[2];     /* Alignment padding to 16 bytes */
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

// IPv6 whitelist exact match hash table
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, struct block_value);
    __uint(max_entries, MAX_WHITELIST_IPV6_LIST_ENTRIES);
} whitelist_ipv6_list SEC(".maps");

// IPv6 whitelist CIDR LPM trie
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_trie_key);
    __type(value, struct block_value);
    __uint(max_entries, MAX_WHITELIST_IPV6_CIDR_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_ipv6_cidr_trie SEC(".maps");

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
 * 填充 pkt_info->ip_protocol 和 pkt_info->tcp_flags
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

    // 只解析 TCP 的标志位
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(ip_data + iph_len);
        
        // 验证 TCP 头边界（至少 20 字节）
        if ((void *)(tcph + 1) > data_end)
            return;
        
        // 提取 TCP 标志位 (tcphdr->tcp_flags 或 th_flags 字段)
        // flags 字段位于 TCP 头的第 13 字节（偏移 12，从 0 开始）
        // struct tcphdr 中通常有 th_flags 或 tcp_flags 字段
        // 使用 bpf_core_read 读取以保持兼容性
        __u8 flags;
        if (bpf_core_read(&flags, sizeof(flags), &tcph->tcp_flags) == 0) {
            pkt_info->tcp_flags = flags;
        }
    }
    // UDP 和 ICMP 不需要特殊处理，只需要记录协议类型
}

/* 检查数据包是否匹配 IP 白名单规则
 * @pi: 包含已解析数据包信息的结构体
 * 返回值: 1=命中白名单(应放行), 0=未命中
 *
 * 白名单优先级最高：命中白名单的数据包直接 XDP_PASS，
 * 跳过后续的 geo-blocking 和黑名单检查
 */
static __always_inline int check_whitelist(struct packet_info *pi) {
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
    } else if (pi->eth_proto == ETH_P_IPV6) {
        // IPv6 精确匹配
        struct in6_addr ipv6_addr;
        __builtin_memcpy(&ipv6_addr.in6_u.u6_addr32, pi->src_ipv6, sizeof(ipv6_addr.in6_u.u6_addr32));
        struct block_value *val = bpf_map_lookup_elem(&whitelist_ipv6_list, &ipv6_addr);
        if (val && val->source_mask != 0) return 1;

        // IPv6 CIDR 匹配
        struct ipv6_trie_key v6_key = {
            .prefixlen = DEFAULT_IPV6_PREFIX,
        };
        __builtin_memcpy(&v6_key.addr.in6_u.u6_addr32, pi->src_ipv6, sizeof(v6_key.addr.in6_u.u6_addr32));
        val = bpf_map_lookup_elem(&whitelist_ipv6_cidr_trie, &v6_key);
        if (val && val->source_mask != 0) return 1;
    }

    return 0; // 未命中白名单
}

/* 检查数据包是否匹配地域封禁规则
 * @pi: 包含已解析数据包信息的结构体
 * 返回值: 1=通过, 0=阻断
 */
static __always_inline int check_geo_blocking(struct packet_info *pi) {
    __u32 key = 0;
    struct geo_config *config = bpf_map_lookup_elem(&geo_config, &key);

    // Early exit if geo-blocking disabled
    if (UNLIKELY(!config || !config->enabled))
        return 1;  // Pass

    // Only process IPv4 packets (IPv6 暂不处理)
    if (pi->eth_proto == ETH_P_IP) {
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

    // Pass for IPv6 or non-IP packets
    return 1;
}

/* 检查数据包是否匹配配置的过滤规则
 * @pi: 包含已解析数据包信息的结构体
 * 返回值: 匹配类型 (MATCH_BY_IP4_EXACT/IP4_CIDR/IP6_EXACT/IP6_CIDR) 或 MATCH_BY_PASS
 *
 * 匹配顺序: IPv4 精确匹配 -> IPv4 CIDR 匹配 -> IPv6 精确匹配 -> IPv6 CIDR 匹配
 */
static __always_inline __u32 match_by_rule(struct packet_info *pi) {
    // ETH_P_IP 宏定义的是 网络字节序的值, pi->eth_proto 从数据包中读出的也是 网络字节序
    // bpf_printk("match_by_rule eth_proto: %d %d\n", pi->eth_proto, bpf_htons(ETH_P_IP));

    // reference: https://docs.kernel.org/next/bpf/map_lpm_trie.html#bpf-map-lookup-elem
    // Process IPv4 packets
    if (pi->eth_proto == ETH_P_IP) {
        // Try exact match first
        // bpf_printk("match_by_rule IP: %d\n", pi->src_ip);
        struct block_value *ipv4_value = bpf_map_lookup_elem(&block_ipv4_list, &pi->src_ip);
        if (ipv4_value && ipv4_value->source_mask != 0) return MATCH_BY_IP4_EXACT;

        // Then try CIDR match using LPM Trie
        struct ipv4_trie_key v4_key = {
            .prefixlen = DEFAULT_IPV4_PREFIX,
            .addr = pi->src_ip
        };
        struct block_value *ipv4_cidr_value = bpf_map_lookup_elem(&block_ipv4_cidr_trie, &v4_key);
        if (ipv4_cidr_value && ipv4_cidr_value->source_mask != 0) return MATCH_BY_IP4_CIDR;

    } else if (pi->eth_proto == ETH_P_IPV6) {
        // Try exact match first - 直接使用 src_ipv6 数组，避免 memset
        struct in6_addr ipv6_addr;
        __builtin_memcpy(&ipv6_addr.in6_u.u6_addr32, pi->src_ipv6, sizeof(ipv6_addr.in6_u.u6_addr32));
        struct block_value *ipv6_value = bpf_map_lookup_elem(&block_ipv6_list, &ipv6_addr);
        if (ipv6_value && ipv6_value->source_mask != 0) return MATCH_BY_IP6_EXACT;

        // Then try CIDR match using LPM Trie - 直接初始化 LPM key
        struct ipv6_trie_key v6_key = {
            .prefixlen = DEFAULT_IPV6_PREFIX,
        };
        __builtin_memcpy(&v6_key.addr.in6_u.u6_addr32, pi->src_ipv6, sizeof(v6_key.addr.in6_u.u6_addr32));
        struct block_value *ipv6_cidr_value = bpf_map_lookup_elem(&block_ipv6_cidr_trie, &v6_key);
        if (ipv6_cidr_value && ipv6_cidr_value->source_mask != 0) return MATCH_BY_IP6_CIDR;
    }
    return MATCH_BY_PASS;
}

/* 解析 IP 层头部信息
 * @pkt_info: 输出参数，填充解析后的数据包信息
 * @data: 数据包起始指针
 * @data_end: 数据包结束指针
 * 返回值: 0=成功, 1=数据包异常(应丢弃), 2=非 IP 协议
 *
 * 处理流程:
 * 1. 解析以太网头
 * 2. 处理 VLAN 标签 (802.1Q/802.1AD)
 * 3. 解析 IPv4 或 IPv6 头部
 * 4. 处理 IPv6 扩展头链
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
    
    // 根据以太网协议类型判断是 IPv4 还是 IPv6
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
        // 常见协议: TCP(6), UDP(17), ICMP(1), ESP(50), AH(51)
        // 这里只做基本验证，不接受未知协议
        if (iph->protocol == 0 || iph->protocol > 255)
            return 1;

        // IPv4 分片处理: 只处理首片分片
        //
        // frag_off 字段结构:
        //   bit 0-12: Fragment Offset (以8字节为单位)
        //   bit 13:   DF (Don't Fragment)
        //   bit 14:   MF (More Fragments)
        //   bit 15:   Reserved
        //
        // IP_OFFSET (0x1FFF) 提取 Fragment Offset 部分
        //
        // 分片类型:
        //   - 首片: offset=0 (可能设置 MF)
        //   - 后续片: offset>0 (可能设置 MF)
        //   - 最后片: offset>0, MF=0
        //
        // 策略: 只处理首片 (offset=0)，丢弃后续分片
        // 原因: 后续分片不包含完整的 IP 头信息，无法提取源 IP
        if (iph->frag_off & bpf_htons(IP_OFFSET))
            return 1;

        // 填充 IPv4 地址信息
        pkt_info->src_ip = iph->saddr;
        pkt_info->dst_ip = iph->daddr;
        pkt_info->ip_protocol = iph->protocol;
        pkt_info->tcp_flags = 0;

        // 解析传输层（TCP 标志位）
        parse_transport_layer(pkt_info, ip_data, iph_len, data_end, iph->protocol);
        
    } else if (pkt_info->eth_proto == ETH_P_IPV6) {
        // IPv6 处理
        struct ipv6hdr *ipv6h = (struct ipv6hdr *)ip_data;
        if ((void *)(ipv6h + 1) > data_end)
            return 1;

        // 复制 IPv6 地址（128 位 = 4 * 32 位）
        __builtin_memcpy(pkt_info->src_ipv6, ipv6h->saddr.in6_u.u6_addr32, sizeof(pkt_info->src_ipv6));
        __builtin_memcpy(pkt_info->dst_ipv6, ipv6h->daddr.in6_u.u6_addr32, sizeof(pkt_info->dst_ipv6));
        pkt_info->ip_protocol = 0;
        pkt_info->tcp_flags = 0;

        // 处理 IPv6 扩展头链
        // 跳过所有扩展头直到找到传输层协议或达到限制
        __u8 nexthdr = ipv6h->nexthdr;

        // 早期退出优化: 如果没有扩展头，直接返回
        // 大多数 IPv6 包没有扩展头，这可以避免不必要的循环
        if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP ||
            nexthdr == 59 || nexthdr == IPPROTO_ICMPV6) {
            return 0;
        }

        void *ext_hdr = (void *)(ipv6h + 1);
        int hdr_count = 0;

        // 常见的 IPv6 扩展头类型
        // 0: Hop-by-Hop Options
        // 43: Routing
        // 44: Fragment (分片数据包，可能没有完整地址信息)
        // 50: Encapsulating Security Payload (ESP)
        // 51: Authentication Header (AH)
        // 60: Destination Options
        // 59: No Next Header (链的末尾)

        while (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP &&
               nexthdr != 59 /* No Next Header */) {
            // 防止 DoS: 限制扩展头数量
            if (hdr_count++ >= MAX_IPV6_EXT_HEADERS)
                return 1;

            // 验证至少有 8 字节 (IPv6 扩展头最小长度)
            if (ext_hdr + 8 > data_end)
                return 1;

            // 读取 nexthdr 字段 (扩展头第一个字节)
            __u8 next = *(__u8 *)ext_hdr;

            // 特殊处理: Fragment 扩展头
            // 需要检查 frag_off 字段 (偏移 2-3 字节)
            if (nexthdr == IPPROTO_FRAGMENT) {
                // 验证 frag_hdr 结构 (8 字节)
                if (ext_hdr + sizeof(struct frag_hdr) > data_end)
                    return 1;
                struct frag_hdr *frag = (struct frag_hdr *)ext_hdr;
                // 如果是后续分片 (offset > 0)，应该丢弃
                // IP6F_OFF_MASK = 0xFFF8，提取 bits 4-15 的分片偏移
                if (frag->frag_off & bpf_htons(IP6F_OFF_MASK))
                    return 1;
            }

            // 更新 nexthdr
            nexthdr = next;

            // 跳过 8 字节 (IPv6 扩展头最小单位)
            ext_hdr += 8;
        }

        // 注意: 当前代码不解析传输层，但仍需正确跳过扩展头
        // 以确保正确处理带扩展头的 IPv6 数据包
    } else {
        return 2; // 不是 IPv4 或 IPv6
    }
    
    return 0;
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

    // 只初始化需要的字段（避免完整 memset，提高性能）
    pkt_info->eth_proto = 0;
    pkt_info->src_ip = 0;
    pkt_info->dst_ip = 0;
    __builtin_memset(pkt_info->src_ipv6, 0, sizeof(pkt_info->src_ipv6));
    __builtin_memset(pkt_info->dst_ipv6, 0, sizeof(pkt_info->dst_ipv6));
    pkt_info->ip_protocol = 0;
    pkt_info->tcp_flags = 0;
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
                    // 上报到 anomaly_events ring buffer
                    bpf_ringbuf_output(&anomaly_events, pkt_info, sizeof(*pkt_info), 0);
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