package blocklog

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	bl := NewManager(100)
	if bl == nil {
		t.Fatal("NewManager returned nil")
	}
	if bl.maxSize != 100 {
		t.Errorf("Expected maxSize 100, got %d", bl.maxSize)
	}
	if bl.Count() != 0 {
		t.Errorf("Expected empty block log, got %d records", bl.Count())
	}
}

func TestAddRecord(t *testing.T) {
	bl := NewManager(10)

	// 添加记录
	record := BlockRecord{
		Timestamp:   1234567890,
		SrcIP:       "192.168.1.1",
		DstIP:       "10.0.0.1",
		MatchType:   "ip4_exact",
		RuleSource:  "manual",
		CountryCode: "CN",
		PacketSize:  64,
	}

	bl.AddRecord(record)

	if bl.Count() != 1 {
		t.Errorf("Expected 1 record, got %d", bl.Count())
	}

	records := bl.GetRecords(1)
	if len(records) != 1 {
		t.Fatalf("Expected 1 record returned, got %d", len(records))
	}

	if records[0].SrcIP != "192.168.1.1" {
		t.Errorf("Expected SrcIP 192.168.1.1, got %s", records[0].SrcIP)
	}
}

func TestMaxSize(t *testing.T) {
	bl := NewManager(3)

	// 添加 5 条记录
	for i := 0; i < 5; i++ {
		bl.AddRecord(BlockRecord{
			SrcIP:      "192.168.1.1",
			MatchType:  "ip4_exact",
			PacketSize: 64,
		})
	}

	// 应该只保留最新的 3 条
	if bl.Count() != 3 {
		t.Errorf("Expected 3 records (maxSize), got %d", bl.Count())
	}
}

func TestGetRecordsByFilter(t *testing.T) {
	bl := NewManager(100)

	// 添加不同类型的记录
	bl.AddRecord(BlockRecord{SrcIP: "192.168.1.1", MatchType: "ip4_exact", RuleSource: "manual"})
	bl.AddRecord(BlockRecord{SrcIP: "192.168.1.2", MatchType: "ip4_cidr", RuleSource: "ipsum"})
	bl.AddRecord(BlockRecord{SrcIP: "192.168.1.3", MatchType: "geo_block", RuleSource: "geo", CountryCode: "US"})
	bl.AddRecord(BlockRecord{SrcIP: "192.168.1.1", MatchType: "ip4_exact", RuleSource: "manual"})

	// 按 MatchType 筛选
	filter := RecordFilter{Date: "2026-01-01", MatchType: "ip4_exact"}
	records := bl.GetRecordsByFilter(filter)
	if len(records) != 2 {
		t.Errorf("Expected 2 ip4_exact records, got %d", len(records))
	}

	// 按 RuleSource 筛选
	filter = RecordFilter{Date: "2026-01-01", RuleSource: "ipsum"}
	records = bl.GetRecordsByFilter(filter)
	if len(records) != 1 {
		t.Errorf("Expected 1 ipsum record, got %d", len(records))
	}

	// 按 SrcIP 筛选
	filter = RecordFilter{Date: "2026-01-01", SrcIP: "192.168.1.1"}
	records = bl.GetRecordsByFilter(filter)
	if len(records) != 2 {
		t.Errorf("Expected 2 records from 192.168.1.1, got %d", len(records))
	}

	// 按 CountryCode 筛选
	filter = RecordFilter{Date: "2026-01-01", CountryCode: "US"}
	records = bl.GetRecordsByFilter(filter)
	if len(records) != 1 {
		t.Errorf("Expected 1 US country record, got %d", len(records))
	}

	// 带 Limit 筛选
	filter = RecordFilter{Date: "2026-01-01", MatchType: "ip4_exact", Limit: 1}
	records = bl.GetRecordsByFilter(filter)
	if len(records) != 1 {
		t.Errorf("Expected 1 record with limit, got %d", len(records))
	}
}

func TestGetStats(t *testing.T) {
	bl := NewManager(100)

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
	record := CreateRecord("192.168.1.1", "10.0.0.1", "ip4_exact", "manual", "CN", 64)

	if record.SrcIP != "192.168.1.1" {
		t.Errorf("Expected SrcIP 192.168.1.1, got %s", record.SrcIP)
	}
	if record.DstIP != "10.0.0.1" {
		t.Errorf("Expected DstIP 10.0.0.1, got %s", record.DstIP)
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
