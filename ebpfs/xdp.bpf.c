//go:build ignore

#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Rule match types
#define MATCH_BY_PASS      0     // No rule matched
#define MATCH_BY_IP4_EXACT  1    // Match IPv4 address exactly
#define MATCH_BY_IP4_CIDR   2    // Match IPv4 address by CIDR block
#define MATCH_BY_IP6_EXACT  3    // Match IPv6 address exactly
#define MATCH_BY_IP6_CIDR   4    // Match IPv6 address by CIDR block
#define MATCH_BY_MAC        5    // Match MAC address exactly

// Maximum number of entries in each map
#define MAX_ENTRIES_SIZE 1024    // Limit to prevent excessive memory usage

// Default prefix lengths for IP lookups
#define DEFAULT_IPV6_PREFIX  128 // Full IPv6 address length for LPM lookup
#define DEFAULT_IPV4_PREFIX  32  // Full IPv4 address length for LPM lookup
#define DEFAULT_KEY 0

/* Packet information structure for processing and event reporting
 * Total size: 68 bytes, packed to avoid padding
 */
struct packet_info {
    // Network layer - IPv4 addresses
    __be32 src_ip;                  // Source IPv4 address
    __be32 dst_ip;                  // Destination IPv4 address

    // Network layer - IPv6 addresses
    __be32 src_ipv6[4];             // Source IPv6 address (128 bits)
    __be32 dst_ipv6[4];             // Destination IPv6 address (128 bits)

    // Transport layer
    __be16 src_port;                // Source port (TCP/UDP)
    __be16 dst_port;                // Destination port (TCP/UDP)

    // Protocol information
    __u16 eth_proto;                // Ethernet protocol type
    __u16 ip_proto;                 // IP protocol number

    // Metadata
    __u32 pkt_size;                 // Total packet size. offset: 60, bytes: 4
    __u32 match_type;               // Type of rule that matched. offset: 64, bytes: 4
} __attribute__((packed));          // 68 bytes

/* eBPF maps definitions
 * All maps are limited to MAX_ENTRIES_SIZE entries
 */

// IPv4 exact match hash table
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __u8);
    __uint(max_entries, MAX_ENTRIES_SIZE);
} ipv4_list SEC(".maps");

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
    __type(value, __u8);
    __uint(max_entries, MAX_ENTRIES_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_cidr_trie SEC(".maps");

// IPv6 exact match hash table
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, __u8);
    __uint(max_entries, MAX_ENTRIES_SIZE);
} ipv6_list SEC(".maps");

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
    __type(value, __u8);
    __uint(max_entries, MAX_ENTRIES_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_cidr_trie SEC(".maps");

// Scratch map for storing packet information
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct packet_info);
    __uint(max_entries, 1);
} scratch SEC(".maps");

// Performance event map for reporting matched packets
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} events SEC(".maps");


/* Check if packet matches any configured rules
 * Returns: Match type if matched, RUN_MODE_PASS if not matched
 * Note: Checks are performed in order: IPv4 -> IPv6
 */
static __always_inline __u32 match_by_rule(struct packet_info *pi) {
    // ETH_P_IP 宏定义的是 网络字节序的值, pi->eth_proto 从数据包中读出的也是 网络字节序
    // bpf_printk("match_by_rule eth_proto: %d %d\n", pi->eth_proto, bpf_htons(ETH_P_IP));

    // reference: https://docs.kernel.org/next/bpf/map_lpm_trie.html#bpf-map-lookup-elem
    // Process IPv4 packets
    if (pi->eth_proto == ETH_P_IP) {
        // Try exact match first
        // bpf_printk("match_by_rule IP: %d\n", pi->src_ip);
        if (bpf_map_lookup_elem(&ipv4_list, &pi->src_ip)) return MATCH_BY_IP4_EXACT;

        // Then try CIDR match using LPM Trie
        struct ipv4_trie_key key = {
            .prefixlen = DEFAULT_IPV4_PREFIX,
            .addr = pi->src_ip
        };
        if (bpf_map_lookup_elem(&ipv4_cidr_trie, &key)) return MATCH_BY_IP4_CIDR;
        
    } else if (pi->eth_proto == ETH_P_IPV6) {
        // Try exact match first
        struct in6_addr ipv6_addr;
        __builtin_memset(&ipv6_addr, 0, sizeof(ipv6_addr));
        __builtin_memcpy(&ipv6_addr, pi->src_ipv6, sizeof(ipv6_addr));
        if (bpf_map_lookup_elem(&ipv6_list, &ipv6_addr)) return MATCH_BY_IP6_EXACT;
        
        // Then try CIDR match using LPM Trie
        struct ipv6_trie_key key = {
            .prefixlen = DEFAULT_IPV6_PREFIX,
            .addr = ipv6_addr
        };
        if (bpf_map_lookup_elem(&ipv6_cidr_trie, &key)) return MATCH_BY_IP6_CIDR;
    }
    return MATCH_BY_PASS;
}

/* Parse TCP/UDP header information
 * @pkt_info: Packet info structure to fill
 * @data: Pointer to start of transport header
 * @data_end: Pointer to end of packet data
 * @proto: IP protocol number (IPPROTO_TCP/IPPROTO_UDP)
 */
static __always_inline void parse_transport(struct packet_info *pkt_info, void *data, void *data_end, __u8 proto) {
    pkt_info->ip_proto = proto;
    pkt_info->src_port = 0;
    pkt_info->dst_port = 0;
    
    switch (proto) {
    case IPPROTO_TCP: {
        if (data + sizeof(struct tcphdr) > data_end)
            return;
        struct tcphdr *tcp = data;

        // 验证 TCP 头长度（考虑 TCP 选项）
        __u8 tcp_hlen = tcp->doff * 4;
        if (tcp_hlen < sizeof(struct tcphdr) || (void *)tcp + tcp_hlen > data_end)
            return;

        pkt_info->src_port = bpf_ntohs(tcp->source);
        pkt_info->dst_port = bpf_ntohs(tcp->dest);
        break;
    }
    case IPPROTO_UDP: {
        if (data + sizeof(struct udphdr) > data_end)
            return;
        struct udphdr *udp = data;

        // UDP 头固定 8 字节，无需额外验证
        pkt_info->src_port = bpf_ntohs(udp->source);
        pkt_info->dst_port = bpf_ntohs(udp->dest);
        break;
    }
    default:
        break;
    }
}

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
        // IPv4
        struct iphdr *iph = (struct iphdr *)ip_data;
        if ((void *)(iph + 1) > data_end)
            return 1;
        
        // 验证 IP 头长度
        if (iph->ihl < 5 || (void *)iph + (iph->ihl * 4) > data_end)
            return 1;
        
        // 跳过 IP 分片（非首片无传输层头）
        if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
            return 1;
        
        // 填充 IPv4 地址信息
        pkt_info->src_ip = iph->saddr;
        pkt_info->dst_ip = iph->daddr;
        
        // 跳转到传输层
        void *transport_data = (void *)iph + (iph->ihl * 4);
        parse_transport(pkt_info, transport_data, data_end, iph->protocol);
        
    } else if (pkt_info->eth_proto == ETH_P_IPV6) {
        // IPv6
        struct ipv6hdr *ipv6h = (struct ipv6hdr *)ip_data;
        if ((void *)(ipv6h + 1) > data_end)
            return 1;
        
        // 复制 IPv6 地址（128 位 = 4 * 32 位）
        pkt_info->src_ipv6[0] = ipv6h->saddr.in6_u.u6_addr32[0];
        pkt_info->src_ipv6[1] = ipv6h->saddr.in6_u.u6_addr32[1];
        pkt_info->src_ipv6[2] = ipv6h->saddr.in6_u.u6_addr32[2];
        pkt_info->src_ipv6[3] = ipv6h->saddr.in6_u.u6_addr32[3];
        
        pkt_info->dst_ipv6[0] = ipv6h->daddr.in6_u.u6_addr32[0];
        pkt_info->dst_ipv6[1] = ipv6h->daddr.in6_u.u6_addr32[1];
        pkt_info->dst_ipv6[2] = ipv6h->daddr.in6_u.u6_addr32[2];
        pkt_info->dst_ipv6[3] = ipv6h->daddr.in6_u.u6_addr32[3];
        
        // 处理 IPv6 扩展头（简化处理，只处理最常见的情况）
        __u8 proto = ipv6h->nexthdr;
        void *transport_data = (void *)(ipv6h + 1);
        
        // 这里可以添加对 IPv6 扩展头的处理
        // 目前简化处理，假设没有扩展头或扩展头已正确处理
        parse_transport(pkt_info, transport_data, data_end, proto);
        
    } else {
        return 2; // 不是 IPv4 或 IPv6
    }
    
    return 0;
}

/* Main XDP program entry point
 * Processes incoming packets and applies filtering rules
 */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct packet_info *pkt_info;
    __u32 key = DEFAULT_KEY;
    __u32 match_type = DEFAULT_KEY;
    
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    // Get scratch map element
    pkt_info = bpf_map_lookup_elem(&scratch, &key);
    if (!pkt_info){
        bpf_printk("Failed to lookup scratch map\n");
        return XDP_PASS;
    }
    __builtin_memset(pkt_info, 0, sizeof(*pkt_info));
    int res = parse_ip_header(pkt_info, data, data_end);
    switch (res) {
        case 0:
            goto submit;  
        case 1:{
            // 数据包有问题
            return XDP_DROP;
        }
        case 2:{
            // 非IP/IPv6
            return XDP_PASS;
        }
    }

submit:
    // Check if the packet matches any rules
    match_type = match_by_rule(pkt_info);
    pkt_info->match_type = match_type;
    // Notify event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, pkt_info, sizeof(*pkt_info));
	
    if (match_type != MATCH_BY_PASS) {
        return XDP_DROP;  // Match rule, drop
    }
    return XDP_PASS;
}