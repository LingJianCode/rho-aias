#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN		*/

// IPv4 分片相关
#define IP_MF 0x2000                 /* More Fragments flag */
#define IP_OFFSET 0x1FFF             /* Fragment offset mask */

/* IP 规则值结构 - 支持来源追踪
 * 用于 eBPF maps 中存储 IP 规则及其来源信息
 * 黑名单：source_mask 标记具体来源（ipsum/waf/manual 等）
 * 白名单：仅用 source_mask != 0 判断存在性，无来源语义
 *
 * 注意: expiry 字段仅由用户态读写，内核侧 XDP 程序不检查过期时间。
 * 过期清理由用户态定时任务完成（删除 map entry 后内核自然不再匹配），
 * 这是因为内核中获取 wall clock 时间戳开销较大，不适合在逐包热路径上使用。
 */
struct block_value {
    __u32 source_mask;  /* 来源位掩码 - 标记哪些来源拥有此规则 */
    __u32 priority;     /* 优先级 (保留字段，用于未来扩展) */
    __u64 expiry;       /* 过期时间戳 (Unix 秒，仅用户态读写，内核不检查) */
} __attribute__((packed));

/* 来源位掩码定义
 * 每个来源占用一个 bit，支持最多 31 个来源
 * 优先级: Manual > WAF > DDoS > Intel
 */
#define SOURCE_MASK_IPSUM     0x01  /* Bit 0: IPSum 威胁情报 */
#define SOURCE_MASK_SPAMHAUS  0x02  /* Bit 1: Spamhaus 威胁情报 */
#define SOURCE_MASK_MANUAL    0x04  /* Bit 2: 手动添加 */
#define SOURCE_MASK_WAF       0x08  /* Bit 3: WAF */
#define SOURCE_MASK_DDoS      0x10  /* Bit 4: DDoS 异常检测 */
#define SOURCE_MASK_RATE_LIMIT 0x20  /* Bit 5: 频率限制封禁 */
#define SOURCE_MASK_ANOMALY     0x40  /* Bit 6: 异常流量检测 */
#define SOURCE_MASK_FAILGUARD   0x80  /* Bit 7: SSH 防爆破 */ 