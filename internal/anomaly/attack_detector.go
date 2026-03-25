package anomaly

import (
	"time"
)

// AttackDetector 攻击检测器
// 基于协议分布统计检测各种 Flood 攻击
type AttackDetector struct {
	config AttacksConfig
}

// NewAttackDetector 创建新的攻击检测器
func NewAttackDetector(config AttacksConfig) *AttackDetector {
	// 设置默认值
	if config.SynFlood.RatioThreshold == 0 {
		config.SynFlood.RatioThreshold = 0.5
	}
	if config.SynFlood.BlockDuration == 0 {
		config.SynFlood.BlockDuration = 60
	}

	if config.UdpFlood.RatioThreshold == 0 {
		config.UdpFlood.RatioThreshold = 0.8
	}
	if config.UdpFlood.BlockDuration == 0 {
		config.UdpFlood.BlockDuration = 60
	}

	if config.IcmpFlood.RatioThreshold == 0 {
		config.IcmpFlood.RatioThreshold = 0.5
	}
	if config.IcmpFlood.BlockDuration == 0 {
		config.IcmpFlood.BlockDuration = 60
	}

	if config.AckFlood.RatioThreshold == 0 {
		config.AckFlood.RatioThreshold = 0.8
	}
	if config.AckFlood.BlockDuration == 0 {
		config.AckFlood.BlockDuration = 60
	}

	return &AttackDetector{
		config: config,
	}
}

// DetectAttack 检测攻击类型
// stats: IP 协议统计
// minPackets: 最小包数阈值
// 返回：检测结果（如果检测到攻击）
func (d *AttackDetector) DetectAttack(stats *IPProtocolStats, minPackets int) []DetectionResult {
	var results []DetectionResult
	totalPackets := stats.TotalPackets

	// 低于最小包数，不检测
	if totalPackets < uint64(minPackets) {
		return results
	}

	now := time.Now()

	// SYN Flood 检测
	if d.config.SynFlood.Enabled && stats.TCPCount > 1000 {
		synRatio := float64(stats.TCPSynCount) / float64(totalPackets)
		if synRatio > d.config.SynFlood.RatioThreshold {
			results = append(results, DetectionResult{
				AttackType:    AttackTypeSynFlood,
				CurrentPPS:    stats.TotalPackets, // 简化：使用总包数作为 PPS
				Threshold:     d.config.SynFlood.RatioThreshold,
				BlockDuration: d.config.SynFlood.BlockDuration,
				Timestamp:     now,
			})
		}
	}

	// UDP Flood 检测
	if d.config.UdpFlood.Enabled && stats.UDPCount > 1000 {
		udpRatio := float64(stats.UDPCount) / float64(totalPackets)
		if udpRatio > d.config.UdpFlood.RatioThreshold {
			results = append(results, DetectionResult{
				AttackType:    AttackTypeUdpFlood,
				CurrentPPS:    stats.TotalPackets,
				Threshold:     d.config.UdpFlood.RatioThreshold,
				BlockDuration: d.config.UdpFlood.BlockDuration,
				Timestamp:     now,
			})
		}
	}

	// ICMP Flood 检测
	if d.config.IcmpFlood.Enabled && stats.ICMPCount > 100 {
		icmpRatio := float64(stats.ICMPCount) / float64(totalPackets)
		if icmpRatio > d.config.IcmpFlood.RatioThreshold {
			results = append(results, DetectionResult{
				AttackType:    AttackTypeIcmpFlood,
				CurrentPPS:    stats.TotalPackets,
				Threshold:     d.config.IcmpFlood.RatioThreshold,
				BlockDuration: d.config.IcmpFlood.BlockDuration,
				Timestamp:     now,
			})
		}
	}

	// ACK Flood 检测
	if d.config.AckFlood.Enabled && stats.TCPCount > 1000 {
		ackRatio := float64(stats.TCPAckCount) / float64(totalPackets)
		if ackRatio > d.config.AckFlood.RatioThreshold {
			results = append(results, DetectionResult{
				AttackType:    AttackTypeAckFlood,
				CurrentPPS:    stats.TotalPackets,
				Threshold:     d.config.AckFlood.RatioThreshold,
				BlockDuration: d.config.AckFlood.BlockDuration,
				Timestamp:     now,
			})
		}
	}

	return results
}

// DetectSynFlood 检测 SYN Flood 攻击
func (d *AttackDetector) DetectSynFlood(stats *IPProtocolStats, minPackets int) *DetectionResult {
	if !d.config.SynFlood.Enabled {
		return nil
	}

	if stats.TotalPackets < uint64(minPackets) || stats.TCPCount < 1000 {
		return nil
	}

	synRatio := float64(stats.TCPSynCount) / float64(stats.TotalPackets)
	if synRatio > d.config.SynFlood.RatioThreshold {
		return &DetectionResult{
			AttackType:    AttackTypeSynFlood,
			CurrentPPS:    stats.TotalPackets,
			Threshold:     d.config.SynFlood.RatioThreshold,
			BlockDuration: d.config.SynFlood.BlockDuration,
			Timestamp:     time.Now(),
		}
	}

	return nil
}

// DetectUdpFlood 检测 UDP Flood 攻击
func (d *AttackDetector) DetectUdpFlood(stats *IPProtocolStats, minPackets int) *DetectionResult {
	if !d.config.UdpFlood.Enabled {
		return nil
	}

	if stats.TotalPackets < uint64(minPackets) || stats.UDPCount < 1000 {
		return nil
	}

	udpRatio := float64(stats.UDPCount) / float64(stats.TotalPackets)
	if udpRatio > d.config.UdpFlood.RatioThreshold {
		return &DetectionResult{
			AttackType:    AttackTypeUdpFlood,
			CurrentPPS:    stats.TotalPackets,
			Threshold:     d.config.UdpFlood.RatioThreshold,
			BlockDuration: d.config.UdpFlood.BlockDuration,
			Timestamp:     time.Now(),
		}
	}

	return nil
}

// DetectIcmpFlood 检测 ICMP Flood 攻击
func (d *AttackDetector) DetectIcmpFlood(stats *IPProtocolStats, minPackets int) *DetectionResult {
	if !d.config.IcmpFlood.Enabled {
		return nil
	}

	if stats.TotalPackets < uint64(minPackets) || stats.ICMPCount < 100 {
		return nil
	}

	icmpRatio := float64(stats.ICMPCount) / float64(stats.TotalPackets)
	if icmpRatio > d.config.IcmpFlood.RatioThreshold {
		return &DetectionResult{
			AttackType:    AttackTypeIcmpFlood,
			CurrentPPS:    stats.TotalPackets,
			Threshold:     d.config.IcmpFlood.RatioThreshold,
			BlockDuration: d.config.IcmpFlood.BlockDuration,
			Timestamp:     time.Now(),
		}
	}

	return nil
}

// DetectAckFlood 检测 ACK Flood 攻击
func (d *AttackDetector) DetectAckFlood(stats *IPProtocolStats, minPackets int) *DetectionResult {
	if !d.config.AckFlood.Enabled {
		return nil
	}

	if stats.TotalPackets < uint64(minPackets) || stats.TCPCount < 1000 {
		return nil
	}

	ackRatio := float64(stats.TCPAckCount) / float64(stats.TotalPackets)
	if ackRatio > d.config.AckFlood.RatioThreshold {
		return &DetectionResult{
			AttackType:    AttackTypeAckFlood,
			CurrentPPS:    stats.TotalPackets,
			Threshold:     d.config.AckFlood.RatioThreshold,
			BlockDuration: d.config.AckFlood.BlockDuration,
			Timestamp:     time.Now(),
		}
	}

	return nil
}
