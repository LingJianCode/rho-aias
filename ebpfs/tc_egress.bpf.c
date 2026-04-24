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
 * - 溢出保护: delta_ns 截断至 2s 防止乘法溢出
 *
 * 依赖:
 * - 内核 5.1+ (bpf_spin_lock)
 * - BPF_MAP_TYPE_HASH (3.19+)
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

// 单条目大小: 8 + 8 + 8 + 4(lock) + 4(padding) = 32 字节
// 注意: 不使用 __attribute__((packed))，因为 bpf_spin_lock 要求 4 字节对齐，
// packed 会导致 lock 地址可能未对齐，触发 -Waddress-of-packed-member 警告
struct flow_limit_state {
    __u64 tokens;              // 当前剩余令牌数 (Bytes)
    __u64 last_update_ns;      // 上次更新时间戳 (ns)
    __u64 fractional;          // 分数令牌余数 (0 ~ 999,999,999)，消除整数截断误差
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

// per-flow 限速状态 Map (HASH)
// Key: 目标 IP (网络字节序)
// Value: struct flow_limit_state
// 注意: 不能使用 LRU_HASH，因为 LRU 隐式淘汰与 bpf_spin_lock 互斥
// 过期条目由 Go 控制面通过 cron 定时清理
struct {
    __uint(type, BPF_MAP_TYPE_HASH);          // 不能用 LRU_HASH + bpf_spin_lock
    __type(key, __u32);                        // Key: dst_ip (网络字节序)
    __type(value, struct flow_limit_state);
    __uint(max_entries, 262144);               // 256k 条目 (~8MB)
} egress_limits SEC(".maps");

// ==========================================
// 3.5 丢包事件上报配置与 RingBuf
// ==========================================

// egress 丢包事件 (上报到用户态)
struct egress_drop_info {
    __be32 dst_ip;          // 目标 IP (网络字节序)
    __u32  pkt_len;         // 被丢弃的包大小 (Bytes)
    __u64  tokens;          // 丢包时的令牌数 (用于诊断)
    __u64  rate_bytes;      // 当时限速速率 (用于诊断)
};

// 丢包事件上报配置
struct egress_drop_event_config {
    __u32 enabled;          // 0=关闭, 1=开启
    __u32 sample_rate;      // 采样率: 每 N 个丢包上报 1 个
    __u32 padding[2];       // 对齐填充
} __attribute__((packed));

// 丢包事件配置 Map (ARRAY, key=0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct egress_drop_event_config);
    __uint(max_entries, 1);
} egress_drop_event_config SEC(".maps");

// 丢包事件 RingBuf (上报到用户态)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1MB buffer size
} egress_drop_events SEC(".maps");

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
        new_state.fractional = 0;

        // 尝试插入 (BPF_NOEXIST 防止覆盖正在使用的条目，处理多核竞争)
        bpf_map_update_elem(&egress_limits, &daddr, &new_state, BPF_NOEXIST);

        // 重新获取指针以进入临界区
        // 无论插入是否成功，都必须重新 lookup 获取有效指针
        val = bpf_map_lookup_elem(&egress_limits, &daddr);
        if (!val)
            return TC_ACT_OK;
    }

    // --- 4. 限流计算 ---
    // BPF 验证器要求: 持有 bpf_spin_lock 期间不能调用任何 helper 函数
    // 因此 bpf_ktime_get_ns() 必须在获取锁之前调用
    // 同时预读 cfg 和 skb 值到局部变量，确保临界区内无外部访问
    __u64 now = bpf_ktime_get_ns();
    __u64 rate = cfg->rate_bytes;
    __u64 burst = cfg->burst_bytes;
    __u32 pkt_len = skb->len;

    bpf_spin_lock(&val->lock);

    __u64 delta_ns = now - val->last_update_ns;

    // [防溢出补丁] 限制最大补票窗口为 2s
    // 防止长时间空闲后 delta_ns 过大导致乘法溢出
    // 2s 上限允许 TCP 在丢包恢复后有足够的令牌池重建 CWND
    // 乘法安全性验证: 2e9 * 1.25e8 (200Mbps) = 2.5e17, 远小于 u64 最大值 1.8e19
    if (delta_ns > 2000000000ULL) {
        delta_ns = 2000000000ULL;
    }

    // 令牌补充: rate 是 Bytes/s, 需要转换为 ns 级别
    // 使用分数令牌追踪，消除整数除法截断误差
    // 公式: ns_tokens = delta_ns * rate + fractional
    //       add_tokens = ns_tokens / 1_000_000_000
    //       fractional = ns_tokens % 1_000_000_000
    __u64 ns_tokens = delta_ns * rate + val->fractional;
    val->fractional = ns_tokens % 1000000000ULL;
    __u64 add_tokens = ns_tokens / 1000000000ULL;
    val->tokens += add_tokens;

    // 钳位 (令牌数不超过 burst 上限)
    if (val->tokens > burst) {
        val->tokens = burst;
    }

    int action = TC_ACT_SHOT; // 默认丢包
    __u64 tokens_at_drop = 0; // 丢包时令牌数（临界区外上报用）

    // 判定是否放行
    if (val->tokens >= (__u64)pkt_len) {
        val->tokens -= (__u64)pkt_len;
        action = TC_ACT_OK;
    } else {
        tokens_at_drop = val->tokens; // 记录丢包时令牌数
    }

    val->last_update_ns = now;
    bpf_spin_unlock(&val->lock);

    // --- 5. 丢包事件上报 (临界区外，可调用 helper 函数) ---
    if (action == TC_ACT_SHOT) {
        __u32 config_key = 0;
        struct egress_drop_event_config *dcfg = bpf_map_lookup_elem(&egress_drop_event_config, &config_key);

        if (dcfg && dcfg->enabled) {
            __u32 sample_rate = dcfg->sample_rate;
            if (sample_rate == 0)
                sample_rate = 100; // 默认采样率，防止除零

            __u32 random_val = bpf_get_prandom_u32();
            if ((random_val % sample_rate) == 0) {
                struct egress_drop_info drop_info = {
                    .dst_ip = daddr,
                    .pkt_len = pkt_len,
                    .tokens = tokens_at_drop,
                    .rate_bytes = rate,
                };
                bpf_ringbuf_output(&egress_drop_events, &drop_info, sizeof(drop_info), 0);
            }
        }
    }

    return action;
}
