package anomaly

import (
	"testing"
)

func TestAttackDetector_DetectSynFlood(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		SynFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			BlockDuration:  60,
		},
	})

	// 测试 SYN Flood 攻击检测
	stats := &IPProtocolStats{
		TCPCount:     2000,
		TCPSynCount:  1500, // 75% SYN 包
		TotalPackets: 2000,
	}

	result := detector.DetectSynFlood(stats, 100)
	if result == nil {
		t.Fatal("Expected SYN flood detection")
	}

	if result.AttackType != AttackTypeSynFlood {
		t.Errorf("Expected AttackTypeSynFlood, got %v", result.AttackType)
	}

	if result.BlockDuration != 60 {
		t.Errorf("Expected BlockDuration=60, got %d", result.BlockDuration)
	}
}

func TestAttackDetector_DetectSynFlow_BelowThreshold(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		SynFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			BlockDuration:  60,
		},
	})

	// 测试正常流量（SYN 包比例低）
	stats := &IPProtocolStats{
		TCPCount:     2000,
		TCPSynCount:  100, // 5% SYN 包
		TotalPackets: 2000,
	}

	result := detector.DetectSynFlood(stats, 100)
	if result != nil {
		t.Error("Expected no SYN flood detection for normal traffic")
	}
}

func TestAttackDetector_DetectUdpFlood(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		UdpFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.8,
			BlockDuration:  60,
		},
	})

	// 测试 UDP Flood 攻击检测
	stats := &IPProtocolStats{
		UDPCount:     5000, // 90% UDP 包
		TotalPackets: 5555,
	}

	result := detector.DetectUdpFlood(stats, 100)
	if result == nil {
		t.Fatal("Expected UDP flood detection")
	}

	if result.AttackType != AttackTypeUdpFlood {
		t.Errorf("Expected AttackTypeUdpFlood, got %v", result.AttackType)
	}
}

func TestAttackDetector_DetectIcmpFlood(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		IcmpFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			BlockDuration:  60,
		},
	})

	// 测试 ICMP Flood 攻击检测
	stats := &IPProtocolStats{
		ICMPCount:    500, // 80% ICMP 包
		TotalPackets: 625,
	}

	result := detector.DetectIcmpFlood(stats, 100)
	if result == nil {
		t.Fatal("Expected ICMP flood detection")
	}

	if result.AttackType != AttackTypeIcmpFlood {
		t.Errorf("Expected AttackTypeIcmpFlood, got %v", result.AttackType)
	}
}

func TestAttackDetector_DetectAckFlood(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		AckFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.8,
			BlockDuration:  60,
		},
	})

	// 测试 ACK Flood 攻击检测
	stats := &IPProtocolStats{
		TCPCount:     3000,
		TCPAckCount:  2500, // 83% ACK 包
		TotalPackets: 3000,
	}

	result := detector.DetectAckFlood(stats, 100)
	if result == nil {
		t.Fatal("Expected ACK flood detection")
	}

	if result.AttackType != AttackTypeAckFlood {
		t.Errorf("Expected AttackTypeAckFlood, got %v", result.AttackType)
	}
}

func TestAttackDetector_DetectAttack_MultipleAttacks(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		SynFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			BlockDuration:  60,
		},
		UdpFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.8,
			BlockDuration:  60,
		},
		IcmpFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			BlockDuration:  60,
		},
		AckFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.8,
			BlockDuration:  60,
		},
	})

	// 测试同时存在 SYN 和 ACK Flood（SYN 包比例更高）
	stats := &IPProtocolStats{
		TCPCount:     3000,
		TCPSynCount:  2000, // 67% SYN 包
		TCPAckCount:  2500, // 83% ACK 包
		TotalPackets: 3000,
	}

	results := detector.DetectAttack(stats, 100)
	if len(results) < 1 {
		t.Fatal("Expected at least one attack detection")
	}

	// 应该检测到 SYN Flood 和 ACK Flood
	attackTypes := make(map[AttackType]bool)
	for _, r := range results {
		attackTypes[r.AttackType] = true
	}

	if !attackTypes[AttackTypeSynFlood] {
		t.Error("Expected SYN flood to be detected")
	}
	if !attackTypes[AttackTypeAckFlood] {
		t.Error("Expected ACK flood to be detected")
	}
}

func TestAttackDetector_DetectAttack_InsufficientPackets(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		SynFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			BlockDuration:  60,
		},
	})

	// 测试包数不足
	stats := &IPProtocolStats{
		TCPCount:     50, // 少于 minPackets
		TCPSynCount:  40,
		TotalPackets: 50,
	}

	results := detector.DetectAttack(stats, 100)
	if len(results) != 0 {
		t.Error("Expected no detection with insufficient packets")
	}
}

func TestAttackDetector_DisabledDetection(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		SynFlood: AttackConfig{
			Enabled:        false, // 禁用
			RatioThreshold: 0.5,
			BlockDuration:  60,
		},
	})

	stats := &IPProtocolStats{
		TCPCount:     2000,
		TCPSynCount:  1500,
		TotalPackets: 2000,
	}

	result := detector.DetectSynFlood(stats, 100)
	if result != nil {
		t.Error("Expected no detection when disabled")
	}
}

func TestAttackDetector_DefaultConfig(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{})

	if detector.config.SynFlood.RatioThreshold != 0.5 {
		t.Errorf("Expected default SynFlood threshold=0.5, got %f", detector.config.SynFlood.RatioThreshold)
	}
	if detector.config.UdpFlood.RatioThreshold != 0.8 {
		t.Errorf("Expected default UdpFlood threshold=0.8, got %f", detector.config.UdpFlood.RatioThreshold)
	}
	if detector.config.IcmpFlood.RatioThreshold != 0.5 {
		t.Errorf("Expected default IcmpFlood threshold=0.5, got %f", detector.config.IcmpFlood.RatioThreshold)
	}
	if detector.config.AckFlood.RatioThreshold != 0.8 {
		t.Errorf("Expected default AckFlood threshold=0.8, got %f", detector.config.AckFlood.RatioThreshold)
	}
}

func TestAttackDetector_DetectSynFlood_ExactThreshold(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		SynFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			MinPackets:     100,
			BlockDuration:  60,
		},
	})

	// 恰好等于阈值（SYN/TCP == 0.5），不应触发（使用 > 而非 >=）
	stats := &IPProtocolStats{
		TCPCount:     2000,
		TCPSynCount:  1000, // 50% SYN，恰好等于阈值
		TotalPackets: 2000,
	}

	result := detector.DetectSynFlood(stats, 100)
	if result != nil {
		t.Error("Expected no detection when ratio equals threshold (not strictly greater)")
	}
}

func TestAttackDetector_DetectUdpFlood_BelowThreshold(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		UdpFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.8,
			MinPackets:     100,
			BlockDuration:  60,
		},
	})

	// UDP 占比低于阈值
	stats := &IPProtocolStats{
		UDPCount:     3000,
		TotalPackets: 10000, // 30% UDP
	}

	result := detector.DetectUdpFlood(stats, 100)
	if result != nil {
		t.Error("Expected no detection when ratio below threshold")
	}
}

func TestAttackDetector_DetectIcmpFlood_BelowThreshold(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		IcmpFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			MinPackets:     100,
			BlockDuration:  60,
		},
	})

	// ICMP 占比低于阈值
	stats := &IPProtocolStats{
		ICMPCount:    200,
		TotalPackets: 1000, // 20% ICMP
	}

	result := detector.DetectIcmpFlood(stats, 100)
	if result != nil {
		t.Error("Expected no detection when ratio below threshold")
	}
}

func TestAttackDetector_DetectAckFlood_BelowThreshold(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		AckFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.8,
			MinPackets:     100,
			BlockDuration:  60,
		},
	})

	// ACK 占比低于阈值
	stats := &IPProtocolStats{
		TCPCount:     2000,
		TCPAckCount:  1000, // 50% ACK
		TotalPackets: 2000,
	}

	result := detector.DetectAckFlood(stats, 100)
	if result != nil {
		t.Error("Expected no detection when ratio below threshold")
	}
}

func TestAttackDetector_DetectSynFlood_ZeroTCPCount(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		SynFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			MinPackets:     100,
			BlockDuration:  60,
		},
	})

	// TCPCount=0，SYN 用 TCPCount 做分母，不应 panic
	stats := &IPProtocolStats{
		TCPCount:     0,
		TCPSynCount:  0,
		TotalPackets: 500,
	}

	result := detector.DetectSynFlood(stats, 100)
	if result != nil {
		t.Error("Expected no detection when TCPCount is 0")
	}
}

func TestAttackDetector_DetectAttack_ThreeSimultaneous(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		SynFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			MinPackets:     100,
			BlockDuration:  60,
		},
		UdpFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.3,
			MinPackets:     100,
			BlockDuration:  60,
		},
		IcmpFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.1,
			MinPackets:     100,
			BlockDuration:  60,
		},
		AckFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.8,
			MinPackets:     100,
			BlockDuration:  60,
		},
	})

	// 混合攻击：SYN + UDP + ICMP 同时触发
	stats := &IPProtocolStats{
		TCPCount:     1000,
		TCPSynCount:  800,  // 80% SYN > 0.5
		TCPAckCount:  500,  // 50% ACK < 0.8，不触发
		UDPCount:     1500, // 1500/4000 = 37.5% > 0.3
		ICMPCount:    500,  // 500/4000 = 12.5% > 0.1
		TotalPackets: 4000,
	}

	results := detector.DetectAttack(stats, 100)
	attackTypes := make(map[AttackType]bool)
	for _, r := range results {
		attackTypes[r.AttackType] = true
	}

	if !attackTypes[AttackTypeSynFlood] {
		t.Error("Expected SYN flood to be detected")
	}
	if !attackTypes[AttackTypeUdpFlood] {
		t.Error("Expected UDP flood to be detected")
	}
	if !attackTypes[AttackTypeIcmpFlood] {
		t.Error("Expected ICMP flood to be detected")
	}
	if attackTypes[AttackTypeAckFlood] {
		t.Error("Expected ACK flood NOT to be detected (below threshold)")
	}
	if len(results) != 3 {
		t.Errorf("Expected exactly 3 attacks detected, got %d", len(results))
	}
}

func TestAttackDetector_MinPackets_PerAttackType(t *testing.T) {
	detector := NewAttackDetector(AttacksConfig{
		SynFlood: AttackConfig{
			Enabled:        true,
			RatioThreshold: 0.5,
			MinPackets:     5000, // 高 MinPackets
			BlockDuration:  60,
		},
	})

	// 全局 minPackets=100 通过，但 SYN MinPackets=5000 不满足
	stats := &IPProtocolStats{
		TCPCount:     2000,
		TCPSynCount:  1500, // 75% > 0.5
		TotalPackets: 2000,
	}

	result := detector.DetectSynFlood(stats, 100)
	if result != nil {
		t.Error("Expected no detection when TCPCount < SynFlood.MinPackets")
	}

	// 满足 SynFlood.MinPackets
	stats2 := &IPProtocolStats{
		TCPCount:     5000,
		TCPSynCount:  4000, // 80% > 0.5
		TotalPackets: 5000,
	}

	result2 := detector.DetectSynFlood(stats2, 100)
	if result2 == nil {
		t.Error("Expected detection when TCPCount >= SynFlood.MinPackets")
	}
}

func TestAttackType_String(t *testing.T) {
	tests := []struct {
		attackType AttackType
		expected   string
	}{
		{AttackTypeNone, "none"},
		{AttackTypeSynFlood, "syn_flood"},
		{AttackTypeUdpFlood, "udp_flood"},
		{AttackTypeIcmpFlood, "icmp_flood"},
		{AttackTypeAckFlood, "ack_flood"},
		{AttackTypeBaselineAnomaly, "baseline_anomaly"},
	}

	for _, tt := range tests {
		if got := tt.attackType.String(); got != tt.expected {
			t.Errorf("AttackType(%d).String() = %s, want %s", tt.attackType, got, tt.expected)
		}
	}
}
