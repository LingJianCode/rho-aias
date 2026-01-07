//go:build ignore

/* TC (Traffic Control) BPF 程序
 *
 * 功能:
 * - 在 TC ingress 钩子处拦截和过滤数据包
 * - 根据源 IP + 目标端口 + 协议 过滤数据包
 * - 支持精确 IP 匹配和 CIDR 匹配 (IPv4/IPv6)
 *
 * 数据包处理流程:
 * 1. 解析以太网头 -> 获取协议类型
 * 2. 处理 VLAN 标签 (如果存在)
 * 3. 解析 IP 层 (IPv4/IPv6)
 * 4. 解析传输层 (TCP/UDP)
 * 5. 根据规则匹配: 精确匹配 -> CIDR 匹配
 * 6. 返回 TC_ACT_SHOT (丢弃) 或 TC_ACT_OK (放行)
 */

#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// TC actions
#define TC_ACT_OK		0
#define TC_ACT_SHOT		2

// IP protocol numbers
#define IPPROTO_TCP		6
#define IPPROTO_UDP		17

// Maximum number of entries in the rules map
#define MAX_ENTRIES_SIZE 1024

/* TC rule key structure
 * 总大小: 8 bytes (对齐到 64 位)
 */
struct tc_rule_key {
    __u32 src_ip;      // 源 IPv4 地址 (主机字节序)
    __u16 dst_port;    // 目标端口 (主机字节序)
    __u16 proto;       // 协议 (IPPROTO_TCP=6, IPPROTO_UDP=17)
    __u16 padding;     // 填充到 8 字节边界
};

/* IPv4 CIDR trie key (LPM_TRIE)
 */
struct ipv4_trie_key {
    __u32 prefixlen;   // CIDR 前缀长度
    __be32 addr;       // IPv4 地址 (网络字节序)
};

/* IPv6 CIDR trie key (LPM_TRIE)
 */
struct ipv6_trie_key {
    __u32 prefixlen;   // CIDR 前缀长度
    struct in6_addr addr;  // IPv6 地址 (网络字节序)
};

/* IPv6 rule key structure (HASH map - 精确匹配)
 * 总大小: 20 bytes
 */
struct tc_ipv6_rule_key {
    struct in6_addr src_ip;  // 源 IPv6 地址 (网络字节序)
    __u16 dst_port;          // 目标端口 (主机字节序)
    __u16 proto;             // 协议 (IPPROTO_TCP=6, IPPROTO_UDP=17)
    __u32 padding;           // 填充到 20 字节
};

/* eBPF map for TC exact IPv4 filtering rules
 * Key: {src_ip, dst_port, proto}
 * Value: __u8 (1 = 启用规则)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tc_rule_key);
    __type(value, __u8);
    __uint(max_entries, MAX_ENTRIES_SIZE);
} tc_rules SEC(".maps");

/* eBPF map for TC IPv4 CIDR filtering rules
 * Key: {prefixlen, addr}
 * Value: struct tc_cidr_value {dst_port, proto}
 */
struct tc_cidr_value {
    __u16 dst_port;    // 目标端口 (主机字节序)
    __u16 proto;       // 协议 (IPPROTO_TCP=6, IPPROTO_UDP=17)
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_trie_key);
    __type(value, struct tc_cidr_value);
    __uint(max_entries, MAX_ENTRIES_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} tc_ipv4_cidr SEC(".maps");

/* eBPF map for TC IPv6 exact filtering rules
 * Key: {src_ip, dst_port, proto}
 * Value: __u8 (1 = 启用规则)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tc_ipv6_rule_key);
    __type(value, __u8);
    __uint(max_entries, MAX_ENTRIES_SIZE);
} tc_ipv6_rules SEC(".maps");

/* eBPF map for TC IPv6 CIDR filtering rules
 * Key: {prefixlen, addr}
 * Value: struct tc_cidr_value {dst_port, proto}
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_trie_key);
    __type(value, struct tc_cidr_value);
    __uint(max_entries, MAX_ENTRIES_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} tc_ipv6_cidr SEC(".maps");

/* 检查 IPv4 数据包是否匹配 TC 过滤规则
 * @src_ip: 源 IPv4 地址 (网络字节序)
 * @dst_port: 目标端口 (网络字节序)
 * @proto: 协议号 (IPPROTO_TCP 或 IPPROTO_UDP)
 * 返回值: 1=匹配 (应丢弃), 0=不匹配
 *
 * 匹配逻辑:
 * 1. 精确匹配 (src_ip + dst_port + proto)
 * 2. CIDR 匹配 (最长前缀匹配)
 */
static __always_inline int match_tc_rule_v4(__u32 src_ip, __u16 dst_port, __u16 proto) {
    struct tc_rule_key key;

    // 转换字节序
    __u32 src_ip_host = bpf_ntohl(src_ip);
    __u16 dst_port_host = bpf_ntohs(dst_port);

    // 1. 精确匹配 (HASH map)
    __builtin_memset(&key, 0, sizeof(key));
    key.src_ip = src_ip_host;
    key.dst_port = dst_port_host;
    key.proto = proto;

    if (bpf_map_lookup_elem(&tc_rules, &key)) {
        return 1;  // 精确匹配
    }

    // 2. CIDR 匹配 (LPM_TRIE map)
    struct ipv4_trie_key v4_key = {
        .prefixlen = 32,
        .addr = src_ip  // 网络字节序
    };

    struct tc_cidr_value *cidr_val = bpf_map_lookup_elem(&tc_ipv4_cidr, &v4_key);
    if (cidr_val && cidr_val->dst_port == dst_port_host && cidr_val->proto == proto) {
        return 1;  // CIDR 匹配
    }

    return 0;  // 未匹配
}

/* 检查 IPv6 数据包是否匹配 TC 过滤规则
 * @src_ip: 源 IPv6 地址指针
 * @dst_port: 目标端口 (网络字节序)
 * @proto: 协议号 (IPPROTO_TCP 或 IPPROTO_UDP)
 * 返回值: 1=匹配 (应丢弃), 0=不匹配
 *
 * 匹配逻辑:
 * 1. 精确匹配 (src_ip + dst_port + proto)
 * 2. CIDR 匹配 (最长前缀匹配)
 */
static __always_inline int match_tc_rule_v6(struct in6_addr *src_ip, __u16 dst_port, __u16 proto) {
    // 转换字节序
    __u16 dst_port_host = bpf_ntohs(dst_port);

    // 1. 精确匹配 (HASH map)
    struct tc_ipv6_rule_key key;
    __builtin_memset(&key, 0, sizeof(key));
    __builtin_memcpy(&key.src_ip, src_ip, sizeof(struct in6_addr));
    key.dst_port = dst_port_host;
    key.proto = proto;

    if (bpf_map_lookup_elem(&tc_ipv6_rules, &key)) {
        return 1;  // 精确匹配
    }

    // 2. CIDR 匹配 (LPM_TRIE map)
    struct ipv6_trie_key v6_key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&v6_key.addr, src_ip, sizeof(struct in6_addr));

    struct tc_cidr_value *cidr_val = bpf_map_lookup_elem(&tc_ipv6_cidr, &v6_key);
    if (cidr_val && cidr_val->dst_port == dst_port_host && cidr_val->proto == proto) {
        return 1;  // CIDR 匹配
    }

    return 0;  // 未匹配
}

/* 解析并过滤数据包
 * @ctx: TC 元数据结构
 * 返回值: TC_ACT_SHOT (丢弃) 或 TC_ACT_OK (放行)
 */
SEC("tc")
int tc_prog(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 基本边界检查
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    // 指向 IP 层的指针
    void *ip_data = (void *)(eth + 1);

    // 处理 VLAN 标签 (802.1Q/802.1AD)
    if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        ip_data = (void *)(vlan + 1);
        eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
    }

    __u16 dst_port = 0;
    __u16 proto = 0;

    // IPv4 处理
    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph = (struct iphdr *)ip_data;

        // 验证 IP 头边界
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_OK;

        // 验证 IP 头长度
        if (iph->ihl < 5 || iph->ihl > 15)
            return TC_ACT_OK;

        __u32 iph_len = iph->ihl * 4;
        if ((void *)iph + iph_len > data_end)
            return TC_ACT_OK;

        // 只处理 TCP 和 UDP 协议
        if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
            return TC_ACT_OK;

        proto = iph->protocol;

        // 指向传输层头部的指针
        void *trans_hdr = (void *)iph + iph_len;

        // 解析 TCP/UDP 头部获取目标端口
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)trans_hdr;
            if ((void *)(tcph + 1) > data_end)
                return TC_ACT_OK;
            dst_port = tcph->dest;
        } else {  // IPPROTO_UDP
            struct udphdr *udph = (struct udphdr *)trans_hdr;
            if ((void *)(udph + 1) > data_end)
                return TC_ACT_OK;
            dst_port = udph->dest;
        }

        // 检查是否匹配过滤规则
        if (match_tc_rule_v4(iph->saddr, dst_port, proto)) {
            return TC_ACT_SHOT;
        }
    }
    // IPv6 处理
    else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)ip_data;

        // 验证 IPv6 头边界
        if ((void *)(ip6h + 1) > data_end)
            return TC_ACT_OK;

        // 只处理 TCP 和 UDP 协议
        if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
            return TC_ACT_OK;

        proto = ip6h->nexthdr;

        // 指向传输层头部的指针 (IPv6 头固定 40 字节)
        void *trans_hdr = (void *)ip6h + sizeof(struct ipv6hdr);

        // 解析 TCP/UDP 头部获取目标端口
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)trans_hdr;
            if ((void *)(tcph + 1) > data_end)
                return TC_ACT_OK;
            dst_port = tcph->dest;
        } else {  // IPPROTO_UDP
            struct udphdr *udph = (struct udphdr *)trans_hdr;
            if ((void *)(udph + 1) > data_end)
                return TC_ACT_OK;
            dst_port = udph->dest;
        }

        // 检查是否匹配过滤规则
        if (match_tc_rule_v6(&ip6h->saddr, dst_port, proto)) {
            return TC_ACT_SHOT;
        }
    }

    // 不匹配任何规则，放行
    return TC_ACT_OK;
}
