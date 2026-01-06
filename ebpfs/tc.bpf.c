//go:build ignore

/* TC (Traffic Control) BPF 程序
 *
 * 功能:
 * - 在 TC ingress 钩子处拦截和过滤数据包
 * - 根据源 IP + 目标端口 + 协议 过滤数据包
 * - 支持 src_ip=0.0.0.0 作为通配符，匹配任意源 IP
 *
 * 数据包处理流程:
 * 1. 解析以太网头 -> 获取协议类型
 * 2. 处理 VLAN 标签 (如果存在)
 * 3. 解析 IP 层 (仅支持 IPv4)
 * 4. 解析传输层 (TCP/UDP)
 * 5. 根据规则匹配 (src_ip + dst_port + proto)
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
    __u32 src_ip;      // 源 IPv4 地址 (0 = 通配符/任意)
    __u16 dst_port;    // 目标端口 (主机字节序)
    __u16 proto;       // 协议 (IPPROTO_TCP=6, IPPROTO_UDP=17)
    __u16 padding;     // 填充到 8 字节边界
};

/* eBPF map for TC filtering rules
 * Key: {src_ip, dst_port, proto}
 * Value: __u8 (1 = 启用规则)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tc_rule_key);
    __type(value, __u8);
    __uint(max_entries, MAX_ENTRIES_SIZE);
} tc_rules SEC(".maps");

/* 检查数据包是否匹配 TC 过滤规则
 * @src_ip: 源 IPv4 地址 (网络字节序)
 * @dst_port: 目标端口 (网络字节序)
 * @proto: 协议号 (IPPROTO_TCP 或 IPPROTO_UDP)
 * 返回值: 1=匹配 (应丢弃), 0=不匹配
 *
 * 匹配逻辑:
 * 1. 首先尝试精确匹配 (src_ip + dst_port + proto)
 * 2. 如果没有匹配，尝试通配符匹配 (src_ip=0 + dst_port + proto)
 * 3. 任一匹配即返回 1
 */
static __always_inline int match_tc_rule(__u32 src_ip, __u16 dst_port, __u16 proto) {
    struct tc_rule_key key;

    // 转换字节序: IP 转为主机序，端口已经是主机序
    __u32 src_ip_host = bpf_ntohl(src_ip);
    __u16 dst_port_host = bpf_ntohs(dst_port);

    // 尝试精确匹配
    __builtin_memset(&key, 0, sizeof(key));
    key.src_ip = src_ip_host;
    key.dst_port = dst_port_host;
    key.proto = proto;

    if (bpf_map_lookup_elem(&tc_rules, &key)) {
        return 1;  // 精确匹配
    }

    // 尝试通配符匹配 (src_ip = 0)
    key.src_ip = 0;
    if (bpf_map_lookup_elem(&tc_rules, &key)) {
        return 1;  // 通配符匹配
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

    // 只处理 IPv4 数据包
    if (eth_proto != ETH_P_IP)
        return TC_ACT_OK;

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

    // 指向传输层头部的指针
    void *trans_hdr = (void *)iph + iph_len;

    __u16 dst_port = 0;

    // 解析 TCP/UDP 头部获取目标端口
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)trans_hdr;
        // 验证 TCP 头边界 (最小 20 字节)
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_OK;
        dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)trans_hdr;
        // 验证 UDP 头边界 (8 字节)
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;
        dst_port = udph->dest;
    }

    // 检查是否匹配过滤规则
    if (match_tc_rule(iph->saddr, dst_port, iph->protocol)) {
        // 匹配规则，丢弃数据包
        return TC_ACT_SHOT;
    }

    // 不匹配任何规则，放行
    return TC_ACT_OK;
}
