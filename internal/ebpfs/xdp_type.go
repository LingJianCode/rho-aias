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

// 来源位掩码常量
// 每个来源占用一个 bit，支持最多 31 个来源
// 优先级: Manual > WAF > DDoS > Intel
const (
	SourceMaskIpsum    = 0x01 // Bit 0: IPSum 威胁情报
	SourceMaskSpamhaus = 0x02 // Bit 1: Spamhaus 威胁情报
	SourceMaskManual   = 0x04 // Bit 2: 手动添加
	SourceMaskWAF      = 0x08 // Bit 3: WAF (未来)
	SourceMaskDDoS     = 0x10 // Bit 4: DDoS 检测 (未来)
	SourceMaskReserved = 0xE0 // Bits 5-7: 保留给未来使用
)

// Rule 规则结构体 - 包含来源信息
type Rule struct {
	Key     string     // IP/CIDR/MAC 地址
	Value   BlockValue // 黑名单规则值
	Sources []string   // 来源列表 (用于显示)
}

// IPv4TrieKey IPv4 CIDR LPM Trie 键结构
type IPv4TrieKey struct {
	PrefixLen uint32 // __u32 - CIDR 前缀长度
	Addr      [4]byte // IPv4 地址
}

// IPv6TrieKey IPv6 CIDR LPM Trie 键结构
type IPv6TrieKey struct {
	PrefixLen uint32   // __u32 - CIDR 前缀长度
	Addr      [16]byte // IPv6 地址
}

// ============================================
// 位掩码操作辅助函数
// ============================================

// SourceIDToMask 将来源标识符转换为位掩码
func SourceIDToMask(source string) uint32 {
	switch source {
	case "ipsum":
		return SourceMaskIpsum
	case "spamhaus":
		return SourceMaskSpamhaus
	case "manual":
		return SourceMaskManual
	case "waf":
		return SourceMaskWAF
	case "ddos":
		return SourceMaskDDoS
	default:
		return 0
	}
}

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
	return sources
}

// AddSource 添加来源到掩码
// new_mask = old_mask | source_bit
func AddSource(mask uint32, source string) uint32 {
	return mask | SourceIDToMask(source)
}

// RemoveSource 从掩码中移除来源
// new_mask = old_mask & ~source_bit
func RemoveSource(mask uint32, source string) uint32 {
	return mask &^ SourceIDToMask(source)
}

// HasSource 检查掩码是否包含指定来源
func HasSource(mask uint32, source string) bool {
	return mask&SourceIDToMask(source) != 0
}

// IsOnlySource 检查掩码是否仅包含指定来源
func IsOnlySource(mask uint32, source string) bool {
	return mask == SourceIDToMask(source)
}

// GetSourceCount 获取掩码中包含的来源数量
func GetSourceCount(mask uint32) int {
	count := 0
	for mask != 0 {
		count += int(mask & 1)
		mask >>= 1
	}
	return count
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
