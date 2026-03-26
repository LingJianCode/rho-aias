package anomaly

import (
	"sync"
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

// ============================================
// 补充测试：PPS 滑动窗口、基线、并发
// ============================================

func TestCollector_UpdatePPS(t *testing.T) {
	collector := NewCollector(5, 5*time.Minute)

	// 第1秒：注入 100 个包
	for i := 0; i < 100; i++ {
		collector.RecordPacket("1.2.3.4", ProtocolTCP, TCPFlagSYN, 64)
	}
	collector.UpdatePPS()

	stats, _ := collector.GetStats("1.2.3.4")
	if stats.Window.CurrentPPS != 100 {
		t.Errorf("Expected CurrentPPS=100, got %d", stats.Window.CurrentPPS)
	}

	// 第2秒：注入 200 个包
	for i := 0; i < 200; i++ {
		collector.RecordPacket("1.2.3.4", ProtocolTCP, TCPFlagSYN, 64)
	}
	collector.UpdatePPS()

	stats, _ = collector.GetStats("1.2.3.4")
	if stats.Window.CurrentPPS != 200 {
		t.Errorf("Expected CurrentPPS=200, got %d", stats.Window.CurrentPPS)
	}

	// ProtocolStats 应被重置（每秒重置）
	if stats.ProtocolStats.TotalPackets != 0 {
		t.Errorf("Expected ProtocolStats reset after UpdatePPS, got TotalPackets=%d", stats.ProtocolStats.TotalPackets)
	}
}

func TestCollector_ProtocolStatsReset_PerSecond(t *testing.T) {
	collector := NewCollector(5, 5*time.Minute)

	// 记录包
	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagSYN, 64)
	collector.RecordPacket("10.0.0.1", ProtocolUDP, 0, 128)

	// UpdatePPS 后 ProtocolStats 应被重置
	collector.UpdatePPS()

	stats, _ := collector.GetStats("10.0.0.1")
	if stats.ProtocolStats.TCPCount != 0 {
		t.Errorf("Expected TCPCount=0 after UpdatePPS, got %d", stats.ProtocolStats.TCPCount)
	}
	if stats.ProtocolStats.UDPCount != 0 {
		t.Errorf("Expected UDPCount=0 after UpdatePPS, got %d", stats.ProtocolStats.UDPCount)
	}
	if stats.ProtocolStats.TotalPackets != 0 {
		t.Errorf("Expected TotalPackets=0 after UpdatePPS, got %d", stats.ProtocolStats.TotalPackets)
	}

	// 再次记录包（新的一秒窗口）
	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagACK, 64)
	stats, _ = collector.GetStats("10.0.0.1")
	if stats.ProtocolStats.TCPCount != 1 {
		t.Errorf("Expected TCPCount=1 in new window, got %d", stats.ProtocolStats.TCPCount)
	}
}

func TestCollector_SlidingWindow(t *testing.T) {
	windowSize := 3
	collector := NewCollector(windowSize, 5*time.Minute)

	// 填充 3 个窗口
	for sec := 1; sec <= 3; sec++ {
		count := sec * 100
		for i := 0; i < count; i++ {
			collector.RecordPacket("10.0.0.1", ProtocolUDP, 0, 64)
		}
		collector.UpdatePPS()
	}

	stats, _ := collector.GetStats("10.0.0.1")
	// 平均 PPS = (100 + 200 + 300) / 3 = 200
	expectedAvg := 200.0
	if stats.Window.AvgPPS != expectedAvg {
		t.Errorf("Expected AvgPPS=%.2f, got %.2f", expectedAvg, stats.Window.AvgPPS)
	}

	// 第4个窗口：环形数组回绕，覆盖第1个位置
	for i := 0; i < 400; i++ {
		collector.RecordPacket("10.0.0.1", ProtocolUDP, 0, 64)
	}
	collector.UpdatePPS()

	stats, _ = collector.GetStats("10.0.0.1")
	// 平均 PPS = (400 + 200 + 300) / 3 = 300
	expectedAvg = 300.0
	if stats.Window.AvgPPS != expectedAvg {
		t.Errorf("Expected AvgPPS=%.2f after wrap, got %.2f", expectedAvg, stats.Window.AvgPPS)
	}

	// CurrentPPS 应为 400
	if stats.Window.CurrentPPS != 400 {
		t.Errorf("Expected CurrentPPS=400, got %d", stats.Window.CurrentPPS)
	}
}

func TestCollector_UpdateAndGetBaseline(t *testing.T) {
	collector := NewCollector(5, 5*time.Minute)

	// 先记录一个 IP
	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagSYN, 64)

	// 不存在的 IP 的基线
	_, exists := collector.GetBaseline("10.0.0.2")
	if exists {
		t.Error("Expected baseline not to exist for non-existent IP")
	}

	// 通过 UpdateBaseline 更新基线
	collector.UpdateBaseline("10.0.0.1", func(bl *Baseline) {
		bl.Mean = 100.0
		bl.M2 = 50.0
		bl.Count = 10
	})

	// 获取基线验证
	bl, exists := collector.GetBaseline("10.0.0.1")
	if !exists {
		t.Fatal("Expected baseline to exist")
	}
	if bl.Mean != 100.0 {
		t.Errorf("Expected Mean=100.0, got %f", bl.Mean)
	}
	if bl.M2 != 50.0 {
		t.Errorf("Expected M2=50.0, got %f", bl.M2)
	}
	if bl.Count != 10 {
		t.Errorf("Expected Count=10, got %d", bl.Count)
	}

	// 验证深拷贝：修改返回值不影响原始数据
	bl.Mean = 999.0
	bl2, _ := collector.GetBaseline("10.0.0.1")
	if bl2.Mean == 999.0 {
		t.Error("GetBaseline should return a deep copy, but original data was modified")
	}
}

func TestCollector_Cleanup(t *testing.T) {
	maxAge := 100 * time.Millisecond
	collector := NewCollector(5, maxAge)

	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagSYN, 64)
	if collector.GetStatsCount() != 1 {
		t.Errorf("Expected 1 IP, got %d", collector.GetStatsCount())
	}

	// 等待过期
	time.Sleep(150 * time.Millisecond)

	// 手动触发 cleanup（通过 cleanup 方法）
	collector.cleanup()

	if collector.GetStatsCount() != 0 {
		t.Errorf("Expected 0 IPs after cleanup, got %d", collector.GetStatsCount())
	}
}

func TestCollector_ConcurrentRecord(t *testing.T) {
	collector := NewCollector(5, 5*time.Minute)
	ip := "10.0.0.1"

	var wg sync.WaitGroup
	numGoroutines := 10
	packetsPerGoroutine := 100

	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < packetsPerGoroutine; i++ {
				collector.RecordPacket(ip, ProtocolTCP, TCPFlagSYN, 64)
			}
		}()
	}
	wg.Wait()

	stats, exists := collector.GetStats(ip)
	if !exists {
		t.Fatal("Expected stats to exist")
	}

	expected := uint64(numGoroutines * packetsPerGoroutine)
	if stats.ProtocolStats.TotalPackets != expected {
		t.Errorf("Expected TotalPackets=%d, got %d", expected, stats.ProtocolStats.TotalPackets)
	}
	if stats.ProtocolStats.TCPCount != expected {
		t.Errorf("Expected TCPCount=%d, got %d", expected, stats.ProtocolStats.TCPCount)
	}
	if stats.ProtocolStats.TCPSynCount != expected {
		t.Errorf("Expected TCPSynCount=%d, got %d", expected, stats.ProtocolStats.TCPSynCount)
	}
}

func TestCollector_DeepCopyIsolation(t *testing.T) {
	collector := NewCollector(5, 5*time.Minute)

	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagSYN, 64)
	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagSYN, 64)
	collector.UpdatePPS()

	// 获取深拷贝
	stats1, _ := collector.GetStats("10.0.0.1")

	// 再次记录包并 UpdatePPS
	collector.RecordPacket("10.0.0.1", ProtocolTCP, TCPFlagSYN, 64)
	collector.UpdatePPS()

	// 深拷贝的数据不应受影响
	if stats1.Window.CurrentPPS == 0 {
		// 第一次 UpdatePPS 后 CurrentPPS 应为 2
		t.Errorf("Deep copy should preserve CurrentPPS, got %d", stats1.Window.CurrentPPS)
	}

	// 获取新的深拷贝
	stats2, _ := collector.GetStats("10.0.0.1")
	if stats2.Window.CurrentPPS != 1 {
		t.Errorf("Expected CurrentPPS=1 (1 packet in new second), got %d", stats2.Window.CurrentPPS)
	}
}
