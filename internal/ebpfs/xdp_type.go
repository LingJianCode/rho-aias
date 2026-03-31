package ebpfs

// BlockValue 黑名单规则值结构 - 支持来源追踪
// 用于 eBPF maps 中存储规则及其来源信息
type BlockValue struct {
	SourceMask uint32 // 来源位掩码 - 标记哪些来源拥有此规则
	Priority   uint32 // 优先级 (保留字段，用于未来扩展)
	Expiry     uint64 // 过期时间戳 (保留字段，用于 TTL 支持)
}

// NewBlockValue 创建新的 BlockValue，仅设置来源掩码
func NewBlockValue(sourceMask uint32) BlockValue {
	return BlockValue{
		SourceMask: sourceMask,
		Priority:   0,
		Expiry:     0,
	}
}

// NewBlockValueWithPreserve 创建新的 BlockValue，保留原有的 Priority 和 Expiry
// 用于更新掩码时保持规则的其他属性
func NewBlockValueWithPreserve(sourceMask uint32, priority uint32, expiry uint64) BlockValue {
	return BlockValue{
		SourceMask: sourceMask,
		Priority:   priority,
		Expiry:     expiry,
	}
}

// 来源位掩码常量
// 每个来源占用一个 bit，支持最多 31 个来源
// 优先级: Manual > WAF > DDoS > Intel
const (
	SourceMaskIpsum      = 0x01 // Bit 0: IPSum 威胁情报
	SourceMaskSpamhaus   = 0x02 // Bit 1: Spamhaus 威胁情报
	SourceMaskManual     = 0x04 // Bit 2: 手动添加
	SourceMaskWAF        = 0x08 // Bit 3: WAF
	SourceMaskDDoS       = 0x10 // Bit 4: DDoS 异常检测
	SourceMaskRateLimit  = 0x20 // Bit 5: 频率限制封禁
	SourceMaskAnomaly    = 0x40 // Bit 6: 异常流量检测
	SourceMaskFailGuard  = 0x80 // Bit 7: SSH 防爆破
)

// Rule 规则结构体 - 包含来源信息
type Rule struct {
	Key     string     // IP/CIDR 地址
	Value   BlockValue // 黑名单规则值
	Sources []string   // 来源列表 (用于显示)
}

// IPv4TrieKey IPv4 CIDR LPM Trie 键结构
type IPv4TrieKey struct {
	PrefixLen uint32 // __u32 - CIDR 前缀长度
	Addr      [4]byte // IPv4 地址
}

// ============================================
// 位掩码操作辅助函数
// ============================================

// MaskToSourceIDs 将位掩码转换为来源标识符列表
func MaskToSourceIDs(mask uint32) []string {
	var sources []string
	if mask&SourceMaskIpsum != 0 {
		sources = append(sources, "ipsum")
	}
	if mask&SourceMaskSpamhaus != 0 {
		sources = append(sources, "spamhaus")
	}
	if mask&SourceMaskManual != 0 {
		sources = append(sources, "manual")
	}
	if mask&SourceMaskWAF != 0 {
		sources = append(sources, "waf")
	}
	if mask&SourceMaskDDoS != 0 {
		sources = append(sources, "ddos")
	}
	if mask&SourceMaskRateLimit != 0 {
		sources = append(sources, "rate_limit")
	}
	if mask&SourceMaskAnomaly != 0 {
		sources = append(sources, "anomaly")
	}
	if mask&SourceMaskFailGuard != 0 {
		sources = append(sources, "failguard")
	}
	return sources
}

// SourceStringToMask 将来源标识符字符串转换为位掩码
func SourceStringToMask(source string) (uint32, bool) {
	switch source {
	case "ipsum":
		return SourceMaskIpsum, true
	case "spamhaus":
		return SourceMaskSpamhaus, true
	case "manual":
		return SourceMaskManual, true
	case "waf":
		return SourceMaskWAF, true
	case "ddos":
		return SourceMaskDDoS, true
	case "rate_limit":
		return SourceMaskRateLimit, true
	case "anomaly":
		return SourceMaskAnomaly, true
	case "failguard":
		return SourceMaskFailGuard, true
	default:
		return 0, false
	}
}

// ============================================
// Geo-Blocking 相关类型
// ============================================

// GeoConfig 地域封禁配置结构 - 与 eBPF C 中的 struct geo_config 对应
type GeoConfig struct {
	Enabled uint32 // 地域封禁启用标志
	Mode    uint32 // 0: whitelist, 1: blacklist
	Padding uint32 // 对齐填充
}

// NewGeoConfig 创建新的 GeoConfig
func NewGeoConfig(enabled bool, mode uint32) GeoConfig {
	enabledVal := uint32(0)
	if enabled {
		enabledVal = 1
	}
	return GeoConfig{
		Enabled: enabledVal,
		Mode:    mode,
		Padding: 0,
	}
}

// ============================================
// Event Reporting 相关类型
// ============================================

// EventConfig 事件上报配置结构 - 与 eBPF C 中的 struct event_config 对应
type EventConfig struct {
	Enabled    uint32   // 事件上报启用标志 (0=禁用, 1=启用)
	SampleRate uint32   // 采样率：每 N 个丢弃包上报 1 个 (例如 1000 = 0.1%)
	Padding    [2]uint32 // 对齐填充
}

// NewEventConfig 创建新的 EventConfig
func NewEventConfig(enabled bool, sampleRate uint32) EventConfig {
	enabledVal := uint32(0)
	if enabled {
		enabledVal = 1
	}
	// 确保采样率至少为 1，防止除零
	if sampleRate == 0 {
		sampleRate = 1000 // 默认采样率
	}
	return EventConfig{
		Enabled:    enabledVal,
		SampleRate: sampleRate,
		Padding:    [2]uint32{0, 0},
	}
}

// DefaultEventConfig 返回默认的事件配置
// 默认关闭上报，采样率 1000 (0.1%)
func DefaultEventConfig() EventConfig {
	return NewEventConfig(false, 1000)
}

// ============================================
// Anomaly Detection 相关类型
// ============================================

// AnomalyConfig 异常检测采样配置结构 - 与 eBPF C 中的 struct anomaly_config 对应
type AnomalyConfig struct {
	Enabled           uint32   // 异常检测采样启用标志 (0=禁用, 1=启用)
	SampleRate        uint32   // 采样率：每 N 个包采样 1 个 (例如 100 = 1%)
	PortFilterEnabled uint32   // 端口过滤启用标志 (0=监控所有端口, 1=仅监控配置的端口)
	Padding           uint32   // 对齐填充
}

// NewAnomalyConfig 创建新的 AnomalyConfig
func NewAnomalyConfig(enabled bool, sampleRate uint32) AnomalyConfig {
	enabledVal := uint32(0)
	if enabled {
		enabledVal = 1
	}
	// 确保采样率至少为 1，防止除零
	if sampleRate == 0 {
		sampleRate = 100 // 默认采样率 1%
	}
	return AnomalyConfig{
		Enabled:           enabledVal,
		SampleRate:        sampleRate,
		PortFilterEnabled: 0,
		Padding:           0,
	}
}

// DefaultAnomalyConfig 返回默认的异常检测配置
// 默认关闭采样，采样率 100 (1%)
func DefaultAnomalyConfig() AnomalyConfig {
	return NewAnomalyConfig(false, 100)
}
