package anomaly

import (
	"time"
)

// ProtocolStatsAggregator 协议统计聚合器
// 用于聚合多个时间窗口的协议统计
type ProtocolStatsAggregator struct {
	windowSize time.Duration
	stats      IPProtocolStats
	timestamp  time.Time
}

// NewProtocolStatsAggregator 创建新的协议统计聚合器
func NewProtocolStatsAggregator(windowSize time.Duration) *ProtocolStatsAggregator {
	return &ProtocolStatsAggregator{
		windowSize: windowSize,
		timestamp:  time.Now(),
	}
}

// Add 添加统计数据
func (a *ProtocolStatsAggregator) Add(stats IPProtocolStats) {
	a.stats.Merge(&stats)
}

// GetStats 获取聚合后的统计
func (a *ProtocolStatsAggregator) GetStats() IPProtocolStats {
	return a.stats
}

// Reset 重置统计
func (a *ProtocolStatsAggregator) Reset() {
	a.stats.Reset()
	a.timestamp = time.Now()
}

// Elapsed 获取经过的时间
func (a *ProtocolStatsAggregator) Elapsed() time.Duration {
	return time.Since(a.timestamp)
}

// ProtocolRatio 协议占比
type ProtocolRatio struct {
	TCP  float64 // TCP 包占比
	UDP  float64 // UDP 包占比
	ICMP float64 // ICMP 包占比
	Other float64 // 其他协议占比
}

// CalculateProtocolRatio 计算协议占比
func CalculateProtocolRatio(stats *IPProtocolStats) ProtocolRatio {
	if stats.TotalPackets == 0 {
		return ProtocolRatio{}
	}

	total := float64(stats.TotalPackets)
	return ProtocolRatio{
		TCP:   float64(stats.TCPCount) / total,
		UDP:   float64(stats.UDPCount) / total,
		ICMP:  float64(stats.ICMPCount) / total,
		Other: float64(stats.OtherCount) / total,
	}
}

// TCPFlagsRatio TCP 标志位占比
type TCPFlagsRatio struct {
	SYN float64 // SYN 包占比
	ACK float64 // ACK 包占比
	RST float64 // RST 包占比
	FIN float64 // FIN 包占比
}

// CalculateTCPFlagsRatio 计算 TCP 标志位占比
func CalculateTCPFlagsRatio(stats *IPProtocolStats) TCPFlagsRatio {
	if stats.TCPCount == 0 {
		return TCPFlagsRatio{}
	}

	tcpTotal := float64(stats.TCPCount)
	return TCPFlagsRatio{
		SYN: float64(stats.TCPSynCount) / tcpTotal,
		ACK: float64(stats.TCPAckCount) / tcpTotal,
		RST: float64(stats.TCPRstCount) / tcpTotal,
		FIN: float64(stats.TCPFinCount) / tcpTotal,
	}
}

// ProtocolSummary 协议统计摘要
type ProtocolSummary struct {
	TotalPackets   uint64        // 总包数
	TotalBytes     uint64        // 总字节数
	ProtocolRatio  ProtocolRatio // 协议占比
	TCPFlagsRatio  TCPFlagsRatio // TCP 标志位占比
	Timestamp      time.Time     // 时间戳
}

// GenerateProtocolSummary 生成协议统计摘要
func GenerateProtocolSummary(stats *IPProtocolStats) ProtocolSummary {
	return ProtocolSummary{
		TotalPackets:   stats.TotalPackets,
		TotalBytes:     stats.TotalBytes,
		ProtocolRatio:  CalculateProtocolRatio(stats),
		TCPFlagsRatio:  CalculateTCPFlagsRatio(stats),
		Timestamp:      time.Now(),
	}
}
