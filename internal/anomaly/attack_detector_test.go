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
