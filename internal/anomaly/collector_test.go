package anomaly

import (
	"testing"
	"time"
)

func TestCollector_RecordPacket(t *testing.T) {
	collector := NewCollector(60, 5*time.Minute)

	// 测试记录 TCP SYN 包
	collector.RecordPacket("192.168.1.1", ProtocolTCP, TCPFlagSYN, 64)

	stats, exists := collector.GetStats("192.168.1.1")
	if !exists {
		t.Fatal("Expected stats to exist for IP")
	}

	if stats.ProtocolStats.TCPCount != 1 {
		t.Errorf("Expected TCPCount=1, got %d", stats.ProtocolStats.TCPCount)
	}
	if stats.ProtocolStats.TCPSynCount != 1 {
		t.Errorf("Expected TCPSynCount=1, got %d", stats.ProtocolStats.TCPSynCount)
	}
	if stats.ProtocolStats.TotalPackets != 1 {
		t.Errorf("Expected TotalPackets=1, got %d", stats.ProtocolStats.TotalPackets)
	}
	if stats.ProtocolStats.TotalBytes != 64 {
		t.Errorf("Expected TotalBytes=64, got %d", stats.ProtocolStats.TotalBytes)
	}
}

func TestCollector_RecordMultiplePackets(t *testing.T) {
	collector := NewCollector(60, 5*time.Minute)

	// 记录多种类型的包
	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagSYN, 64)
	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagACK, 64)
	collector.RecordPacket("10.0.0.1", ProtocolUDP, 0, 128)
	collector.RecordPacket("10.0.0.1", ProtocolICMP, 0, 56)

	stats, _ := collector.GetStats("10.0.0.1")

	if stats.ProtocolStats.TCPCount != 2 {
		t.Errorf("Expected TCPCount=2, got %d", stats.ProtocolStats.TCPCount)
	}
	if stats.ProtocolStats.TCPSynCount != 1 {
		t.Errorf("Expected TCPSynCount=1, got %d", stats.ProtocolStats.TCPSynCount)
	}
	if stats.ProtocolStats.TCPAckCount != 1 {
		t.Errorf("Expected TCPAckCount=1, got %d", stats.ProtocolStats.TCPAckCount)
	}
	if stats.ProtocolStats.UDPCount != 1 {
		t.Errorf("Expected UDPCount=1, got %d", stats.ProtocolStats.UDPCount)
	}
	if stats.ProtocolStats.ICMPCount != 1 {
		t.Errorf("Expected ICMPCount=1, got %d", stats.ProtocolStats.ICMPCount)
	}
	if stats.ProtocolStats.TotalPackets != 4 {
		t.Errorf("Expected TotalPackets=4, got %d", stats.ProtocolStats.TotalPackets)
	}
}

func TestCollector_RemoveIP(t *testing.T) {
	collector := NewCollector(60, 5*time.Minute)

	collector.RecordPacket("192.168.1.1", ProtocolTCP, TCPFlagSYN, 64)
	collector.RemoveIP("192.168.1.1")

	_, exists := collector.GetStats("192.168.1.1")
	if exists {
		t.Error("Expected IP to be removed")
	}
}

func TestCollector_GetAllStats(t *testing.T) {
	collector := NewCollector(60, 5*time.Minute)

	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagSYN, 64)
	collector.RecordPacket("10.0.0.2", ProtocolUDP, 0, 128)

	allStats := collector.GetAllStats()
	if len(allStats) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(allStats))
	}
}

func TestCollector_GetStatsCount(t *testing.T) {
	collector := NewCollector(60, 5*time.Minute)

	if collector.GetStatsCount() != 0 {
		t.Errorf("Expected 0 IPs initially, got %d", collector.GetStatsCount())
	}

	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagSYN, 64)
	collector.RecordPacket("10.0.0.2", ProtocolUDP, 0, 128)

	if collector.GetStatsCount() != 2 {
		t.Errorf("Expected 2 IPs, got %d", collector.GetStatsCount())
	}
}

func TestIPProtocolStats_Merge(t *testing.T) {
	stats1 := IPProtocolStats{
		TCPCount:     10,
		TCPSynCount:  5,
		UDPCount:     3,
		TotalPackets: 15,
		TotalBytes:   1500,
	}

	stats2 := IPProtocolStats{
		TCPCount:     5,
		TCPSynCount:  2,
		UDPCount:     7,
		TotalPackets: 12,
		TotalBytes:   1200,
	}

	stats1.Merge(&stats2)

	if stats1.TCPCount != 15 {
		t.Errorf("Expected TCPCount=15, got %d", stats1.TCPCount)
	}
	if stats1.TCPSynCount != 7 {
		t.Errorf("Expected TCPSynCount=7, got %d", stats1.TCPSynCount)
	}
	if stats1.UDPCount != 10 {
		t.Errorf("Expected UDPCount=10, got %d", stats1.UDPCount)
	}
	if stats1.TotalPackets != 27 {
		t.Errorf("Expected TotalPackets=27, got %d", stats1.TotalPackets)
	}
	if stats1.TotalBytes != 2700 {
		t.Errorf("Expected TotalBytes=2700, got %d", stats1.TotalBytes)
	}
}

func TestIPProtocolStats_Reset(t *testing.T) {
	stats := IPProtocolStats{
		TCPCount:     10,
		TCPSynCount:  5,
		UDPCount:     3,
		TotalPackets: 15,
		TotalBytes:   1500,
	}

	stats.Reset()

	if stats.TCPCount != 0 {
		t.Errorf("Expected TCPCount=0 after reset, got %d", stats.TCPCount)
	}
	if stats.TotalPackets != 0 {
		t.Errorf("Expected TotalPackets=0 after reset, got %d", stats.TotalPackets)
	}
}
