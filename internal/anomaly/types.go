package anomaly

import "time"

// ============================================
// 配置相关类型
// ============================================

// AnomalyDetectionConfig 异常检测配置
type AnomalyDetectionConfig struct {
	Enabled        bool                 `yaml:"enabled"`         // 总开关
	SampleRate     int                  `yaml:"sample_rate"`     // 采样率 1/N（100 表示 1%）
	CheckInterval  int                  `yaml:"check_interval"`  // 检测间隔（秒）
	MinPackets     int                  `yaml:"min_packets"`     // 最小包数（少于此值不检测）
	CleanupInterval int                 `yaml:"cleanup_interval"` // 清理过期数据间隔（秒）
	BlockDuration  int                  `yaml:"block_duration"`  // 临时封禁时长（秒）
	Baseline       BaselineConfig       `yaml:"baseline"`        // 3σ 基线配置
	Attacks        AttacksConfig        `yaml:"attacks"`         // 攻击类型配置
}

// BaselineConfig 3σ 基线检测配置
type BaselineConfig struct {
	MinSampleCount  int     `yaml:"min_sample_count"`  // 最小样本数
	SigmaMultiplier float64 `yaml:"sigma_multiplier"`  // σ 倍数
	MinThreshold    int     `yaml:"min_threshold"`     // 最小 PPS 阈值
	MaxAge          int     `yaml:"max_age"`           // 基线最大年龄（秒）
}

// AttacksConfig 攻击类型配置
type AttacksConfig struct {
	SynFlood  AttackConfig `yaml:"syn_flood"`
	UdpFlood  AttackConfig `yaml:"udp_flood"`
	IcmpFlood AttackConfig `yaml:"icmp_flood"`
	AckFlood  AttackConfig `yaml:"ack_flood"`
}

// AttackConfig 单个攻击类型配置
type AttackConfig struct {
	Enabled           bool    `yaml:"enabled"`
	RatioThreshold    float64 `yaml:"ratio_threshold"` // 协议占比阈值
	BlockDuration     int     `yaml:"block_duration"`  // 封禁时长（秒）
}

// ============================================
// 统计数据类型
// ============================================

// IPProtocolStats IP 协议统计
type IPProtocolStats struct {
	TCPCount     uint64 // TCP 包总数
	TCPSynCount  uint64 // TCP SYN 包数
	TCPAckCount  uint64 // TCP ACK 包数
	TCPRstCount  uint64 // TCP RST 包数
	TCPFinCount  uint64 // TCP FIN 包数
	UDPCount     uint64 // UDP 包总数
	ICMPCount    uint64 // ICMP 包总数
	OtherCount   uint64 // 其他协议包数
	TotalBytes   uint64 // 总字节数
	TotalPackets uint64 // 总包数
}

// Merge 合并另一个统计到当前统计
func (s *IPProtocolStats) Merge(other *IPProtocolStats) {
	s.TCPCount += other.TCPCount
	s.TCPSynCount += other.TCPSynCount
	s.TCPAckCount += other.TCPAckCount
	s.TCPRstCount += other.TCPRstCount
	s.TCPFinCount += other.TCPFinCount
	s.UDPCount += other.UDPCount
	s.ICMPCount += other.ICMPCount
	s.OtherCount += other.OtherCount
	s.TotalBytes += other.TotalBytes
	s.TotalPackets += other.TotalPackets
}

// Reset 重置统计
func (s *IPProtocolStats) Reset() {
	s.TCPCount = 0
	s.TCPSynCount = 0
	s.TCPAckCount = 0
	s.TCPRstCount = 0
	s.TCPFinCount = 0
	s.UDPCount = 0
	s.ICMPCount = 0
	s.OtherCount = 0
	s.TotalBytes = 0
	s.TotalPackets = 0
}

// IPStats IP 统计数据（包含滑动窗口）
type IPStats struct {
	IP           string
	ProtocolStats IPProtocolStats
	Window       SlidingWindow // 滑动窗口统计
	Baseline     Baseline      // 基线数据
	LastUpdate   time.Time
	FirstSeen    time.Time
}

// SlidingWindow 滑动窗口统计
type SlidingWindow struct {
	PPSHistory []uint64 // 历史 PPS 数据（环形数组）
	PPSIndex   int      // 当前索引
	WindowSize int      // 窗口大小（秒）
	CurrentPPS uint64   // 当前 PPS
	AvgPPS     float64  // 平均 PPS
}

// Baseline 3σ 基线数据（Welford 算法）
type Baseline struct {
	Mean        float64   // 均值
	M2          float64   // 二阶矩（用于计算方差）
	Count       uint64    // 样本数
	LastUpdated time.Time // 最后更新时间
}

// ============================================
// 攻击检测结果类型
// ============================================

// AttackType 攻击类型
type AttackType int

const (
	AttackTypeNone AttackType = iota
	AttackTypeSynFlood
	AttackTypeUdpFlood
	AttackTypeIcmpFlood
	AttackTypeAckFlood
	AttackTypeBaselineAnomaly // 3σ 基线异常
)

func (a AttackType) String() string {
	switch a {
	case AttackTypeSynFlood:
		return "syn_flood"
	case AttackTypeUdpFlood:
		return "udp_flood"
	case AttackTypeIcmpFlood:
		return "icmp_flood"
	case AttackTypeAckFlood:
		return "ack_flood"
	case AttackTypeBaselineAnomaly:
		return "baseline_anomaly"
	default:
		return "none"
	}
}

// DetectionResult 检测结果
type DetectionResult struct {
	IP           string
	AttackType   AttackType
	CurrentPPS   uint64
	Threshold    float64
	BlockDuration int // 封禁时长（秒）
	Timestamp    time.Time
}

// ============================================
// Ring Buffer 事件类型
// ============================================

// PacketSample 采样数据包事件（从 eBPF 上报）
type PacketSample struct {
	SrcIP      [4]byte // 源 IPv4 地址
	Protocol   uint8   // 协议类型 (TCP=6, UDP=17, ICMP=1)
	TCPFlags   uint8   // TCP 标志位 (SYN=0x02, ACK=0x10, etc.)
	PktSize    uint32  // 数据包大小
	Timestamp  uint64  // 时间戳（纳秒）
	Reserved   [2]uint32 // 保留字段
}

// 协议类型常量
const (
	ProtocolTCP  = 6
	ProtocolUDP  = 17
	ProtocolICMP = 1
)

// TCP 标志位常量
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)
