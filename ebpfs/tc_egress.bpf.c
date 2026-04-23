//go:build ignore

/* TC (Traffic Control) Egress 限速 eBPF 程序
 *
 * 功能:
 * - 在网卡 egress 方向（数据包离开网卡前）进行令牌桶限速
 * - 基于目标 IP 进行 per-flow 限速
 * - 支持控制面热更新全局限速配置
 *
 * 数据包处理流程:
 * 1. 检查全局开关（enable），关闭时直接放行
 * 2. 验证 IPv4/TCP 协议
 * 3. 以目标 IP 为 key 查找限速状态
 * 4. 未命中时原子插入新状态（初始令牌满额）
 * 5. 获取自旋锁，进入临界区
 * 6. 计算时间差，补充令牌（防溢出截断）
 * 7. 对比令牌与包大小，判决放行/丢包
 * 8. 更新令牌时间戳，释放锁
 *
 * 安全特性:
 * - IPv4 分片: 处理首片和非首片（非首片无法获取端口信息，但令牌桶逻辑一致）
 * - 边界检查: 所有指针访问前进行边界验证
 * - 协议检查: 仅处理 TCP（可扩展）
 * - 溢出保护: delta_ns 截断至 100ms 防止乘法溢出
 *
 * 依赖:
 * - 内核 5.1+ (bpf_spin_lock)
 * - BPF_MAP_TYPE_LRU_HASH (4.10+)
 */

#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* TC 返回值常量 (linux/pkt_cls.h 中的宏不在 BTF 中，需手动定义)
 * 参考: https://docs.kernel.org/bpf/bpf_devel_QA.html
 */
#ifndef TC_ACT_OK
#define TC_ACT_OK         0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT        2
#endif

char __license[] SEC("license") = "GPL";

// 单条目大小: 8 + 8 + 4(lock) + 4(padding) = 24 字节
// 注意: 不使用 __attribute__((packed))，因为 bpf_spin_lock 要求 4 字节对齐，
// packed 会导致 lock 地址可能未对齐，触发 -Waddress-of-packed-member 警告
struct flow_limit_state {
    __u64 tokens;              // 当前剩余令牌数 (Bytes)
    __u64 last_update_ns;      // 上次更新时间戳 (ns)
    struct bpf_spin_lock lock; // 自旋锁，保护多核并发读写
};

// ==========================================
// 2. 全局配置结构体 (通过 ARRAY Map 传递)
// 与现有 geo_config / anomaly_config 模式一致
// ==========================================
struct egress_limit_config {
    __u32 enabled;       /* 0=关闭(直通), 1=开启 */
    __u32 padding;       /* 对齐填充 */
    __u64 rate_bytes;    /* 全局统一限速值 (Bytes/s) */
    __u64 burst_bytes;   /* 全局统一突发上限 (Bytes) */
} __attribute__((packed));

// ==========================================
// 3. Map 定义
// ==========================================

// 全局配置 Map (ARRAY, key=0)
// 用于控制面热更新限速参数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct egress_limit_config);
    __uint(max_entries, 1);
} egress_limit_config SEC(".maps");

// per-flow 限速状态 Map (LRU_HASH)
// Key: 目标 IP (网络字节序)
// Value: struct flow_limit_state
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);                    // Key: dst_ip (网络字节序)
    __type(value, struct flow_limit_state);
    __uint(max_entries, 262144);           // 256k 条目，减少 LRU 淘汰概率 (~6MB)
} egress_limits SEC(".maps");

// ==========================================
// 4. 协议类型常量
// ==========================================
#ifndef IPPROTO_TCP
#define IPPROTO_TCP  6
#endif

// ==========================================
// 5. 核心逻辑入口 (TC Egress)
// ==========================================
SEC("tc")
int egress_limit(struct __sk_buff *skb)
{
    // --- 1. 全局开关检查 ---
    __u32 config_key = 0;
    struct egress_limit_config *cfg = bpf_map_lookup_elem(&egress_limit_config, &config_key);
    if (!cfg || !cfg->enabled) {
        return TC_ACT_OK;
    }

    // --- 2. 协议安全检查 ---
    // 仅处理 IPv4
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 边界检查：确保以太网头 + IP头 在数据范围内
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    struct iphdr *iph = data + sizeof(struct ethhdr);

    // 仅限制 TCP 流量 (可根据需要扩展到 UDP 等)
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // --- 3. 查表与懒加载初始化 ---
    __u32 daddr = iph->daddr;
    struct flow_limit_state *val = bpf_map_lookup_elem(&egress_limits, &daddr);

    if (!val) {
        // --- 初始化新流 ---
        struct flow_limit_state new_state = {};

        // 初始令牌给满 (使用全局配置的 burst 值)
        new_state.tokens = cfg->burst_bytes;
        new_state.last_update_ns = bpf_ktime_get_ns();

        // 尝试插入 (BPF_NOEXIST 防止覆盖正在使用的条目，处理多核竞争)
        long ret = bpf_map_update_elem(&egress_limits, &daddr, &new_state, BPF_NOEXIST);

        // 重新获取指针以进入临界区
        // 无论插入是否成功，都必须重新 lookup 获取有效指针
        val = bpf_map_lookup_elem(&egress_limits, &daddr);
        if (!val)
            return TC_ACT_OK;
    }

    // --- 4. 限流计算 (临界区) ---
    bpf_spin_lock(&val->lock);

    __u64 now = bpf_ktime_get_ns();
    __u64 delta_ns = now - val->last_update_ns;

    // [防溢出补丁] 限制最大补票窗口为 100ms
    // 防止长时间空闲后 delta_ns 过大导致乘法溢出
    if (delta_ns > 100000000ULL) {
        delta_ns = 100000000ULL;
    }

    // 从全局配置读取速率进行计算
    // rate_bytes 是 Bytes/s, 需要转换为 ns 级别
    // 公式: add_tokens = delta_ns * rate_bytes / 1_000_000_000
    __u64 add_tokens = delta_ns * cfg->rate_bytes / 1000000000ULL;
    val->tokens += add_tokens;

    // 钳位 (直接使用全局 Burst 上限)
    if (val->tokens > cfg->burst_bytes) {
        val->tokens = cfg->burst_bytes;
    }

    int action = TC_ACT_SHOT; // 默认丢包

    // 判定是否放行
    if (val->tokens >= (__u64)skb->len) {
        val->tokens -= (__u64)skb->len;
        action = TC_ACT_OK;
    }

    val->last_update_ns = now;
    bpf_spin_unlock(&val->lock);

    return action;
}
