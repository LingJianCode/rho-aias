package blocklog

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	bl := NewManager()
	if bl == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestAddRecord(t *testing.T) {
	bl := NewManager()

	// 添加记录
	record := BlockRecord{
		Timestamp:   1234567890,
		SrcIP:       "192.168.1.1",
		DstIP:       "10.0.0.1",
		DstPort:     443,
		MatchType:   "ip4_exact",
		RuleSource:  "manual",
		CountryCode: "CN",
		PacketSize:  64,
	}

	bl.AddRecord(record)

	// 验证计数器更新
	stats := bl.GetStats()
	if stats.TotalBlocked != 1 {
		t.Errorf("Expected total 1, got %d", stats.TotalBlocked)
	}
}

func TestGetStats(t *testing.T) {
	bl := NewManager()

	// 添加记录
	bl.AddRecord(BlockRecord{SrcIP: "192.168.1.1", MatchType: "ip4_exact", RuleSource: "manual"})
	bl.AddRecord(BlockRecord{SrcIP: "192.168.1.2", MatchType: "ip4_exact", RuleSource: "manual"})
	bl.AddRecord(BlockRecord{SrcIP: "192.168.1.3", MatchType: "geo_block", RuleSource: "geo", CountryCode: "US"})
	bl.AddRecord(BlockRecord{SrcIP: "192.168.1.4", MatchType: "geo_block", RuleSource: "geo", CountryCode: "CN"})

	stats := bl.GetStats()

	// 无 DB 时 GetStats 返回内存快照（融合查询降级为纯内存）
	if stats.TotalBlocked != 4 {
		t.Errorf("Expected total 4 (memory snapshot), got %d", stats.TotalBlocked)
	}
	if stats.ByRuleSource["manual"] != 2 {
		t.Errorf("Expected by_rule_source.manual=2, got %d", stats.ByRuleSource["manual"])
	}
	if stats.ByRuleSource["geo"] != 2 {
		t.Errorf("Expected by_rule_source.geo=2, got %d", stats.ByRuleSource["geo"])
	}
}

func TestCreateRecord(t *testing.T) {
	record := CreateRecord("192.168.1.1", "10.0.0.1", "ip4_exact", "manual", "CN", 443, 64)

	if record.SrcIP != "192.168.1.1" {
		t.Errorf("Expected SrcIP 192.168.1.1, got %s", record.SrcIP)
	}
	if record.DstIP != "10.0.0.1" {
		t.Errorf("Expected DstIP 10.0.0.1, got %s", record.DstIP)
	}
	if record.DstPort != 443 {
		t.Errorf("Expected DstPort 443, got %d", record.DstPort)
	}
	if record.MatchType != "ip4_exact" {
		t.Errorf("Expected MatchType ip4_exact, got %s", record.MatchType)
	}
	if record.RuleSource != "manual" {
		t.Errorf("Expected RuleSource manual, got %s", record.RuleSource)
	}
	if record.CountryCode != "CN" {
		t.Errorf("Expected CountryCode CN, got %s", record.CountryCode)
	}
	if record.PacketSize != 64 {
		t.Errorf("Expected PacketSize 64, got %d", record.PacketSize)
	}
	if record.Timestamp == 0 {
		t.Error("Expected Timestamp to be set")
	}
}
