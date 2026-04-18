package manual

import (
	"testing"
	"time"
)

func TestNewRuleCacheData(t *testing.T) {
	data := NewRuleCacheData()

	if data == nil {
		t.Fatal("NewRuleCacheData() returned nil")
	}
	if data.Version != 1 {
		t.Errorf("Version = %d, want 1", data.Version)
	}
	if data.Rules == nil {
		t.Error("Rules map should not be nil")
	}
	if len(data.Rules) != 0 {
		t.Errorf("Rules length = %d, want 0", len(data.Rules))
	}
}

func TestNewRuleEntry(t *testing.T) {
	value := "192.168.1.1"
	entry := NewRuleEntry(value)

	if entry == nil {
		t.Fatal("NewRuleEntry() returned nil")
	}
	if entry.Value != value {
		t.Errorf("Value = %v, want %v", entry.Value, value)
	}
	if entry.Remark != "" {
		t.Errorf("Remark = %v, want empty", entry.Remark)
	}
	if entry.AddedAt.IsZero() {
		t.Error("AddedAt should not be zero")
	}
}

func TestNewRuleEntryWithRemark(t *testing.T) {
	entry := NewRuleEntryWithRemark("10.0.0.1", "test remark")

	if entry.Value != "10.0.0.1" {
		t.Errorf("Value = %v, want 10.0.0.1", entry.Value)
	}
	if entry.Remark != "test remark" {
		t.Errorf("Remark = %v, want 'test remark'", entry.Remark)
	}
	if entry.AddedAt.IsZero() {
		t.Error("AddedAt should not be zero")
	}
}

func TestRuleCacheData_AddRule(t *testing.T) {
	data := NewRuleCacheData()

	entry1 := NewRuleEntry("192.168.1.1")
	data.AddRule(*entry1)

	if len(data.Rules) != 1 {
		t.Errorf("Rules length = %d, want 1", len(data.Rules))
	}

	// Add same value again (should update)
	entry2 := NewRuleEntry("192.168.1.1")
	data.AddRule(*entry2)

	if len(data.Rules) != 1 {
		t.Errorf("Rules length after duplicate = %d, want 1", len(data.Rules))
	}

	// Add different value
	entry3 := NewRuleEntry("10.0.0.1")
	data.AddRule(*entry3)

	if len(data.Rules) != 2 {
		t.Errorf("Rules length = %d, want 2", len(data.Rules))
	}
}

func TestRuleCacheData_RemoveRule(t *testing.T) {
	data := NewRuleCacheData()

	// Add some rules
	data.AddRule(*NewRuleEntry("192.168.1.1"))
	data.AddRule(*NewRuleEntry("10.0.0.1"))
	data.AddRule(*NewRuleEntry("172.16.0.1"))

	// Remove one
	data.RemoveRule("10.0.0.1")

	if len(data.Rules) != 2 {
		t.Errorf("Rules length = %d, want 2", len(data.Rules))
	}

	// Remove non-existent (should not error)
	data.RemoveRule("1.1.1.1")

	if len(data.Rules) != 2 {
		t.Errorf("Rules length after removing non-existent = %d, want 2", len(data.Rules))
	}
}

func TestRuleCacheData_HasRule(t *testing.T) {
	data := NewRuleCacheData()

	data.AddRule(*NewRuleEntry("192.168.1.1"))

	if !data.HasRule("192.168.1.1") {
		t.Error("HasRule() should return true for existing rule")
	}

	if data.HasRule("10.0.0.1") {
		t.Error("HasRule() should return false for non-existing rule")
	}
}

func TestRuleCacheData_RuleCount(t *testing.T) {
	data := NewRuleCacheData()

	if data.RuleCount() != 0 {
		t.Errorf("RuleCount() = %d, want 0", data.RuleCount())
	}

	data.AddRule(*NewRuleEntry("192.168.1.1"))
	if data.RuleCount() != 1 {
		t.Errorf("RuleCount() = %d, want 1", data.RuleCount())
	}

	data.AddRule(*NewRuleEntry("10.0.0.1"))
	if data.RuleCount() != 2 {
		t.Errorf("RuleCount() = %d, want 2", data.RuleCount())
	}

	data.RemoveRule("192.168.1.1")
	if data.RuleCount() != 1 {
		t.Errorf("RuleCount() = %d, want 1", data.RuleCount())
	}
}

func TestRuleCacheData_GetValues(t *testing.T) {
	data := NewRuleCacheData()

	// Empty data
	values := data.GetValues()
	if len(values) != 0 {
		t.Errorf("GetValues() length = %d, want 0", len(values))
	}

	// Add some rules
	expectedValues := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}
	for _, v := range expectedValues {
		data.AddRule(*NewRuleEntry(v))
	}

	values = data.GetValues()
	if len(values) != len(expectedValues) {
		t.Errorf("GetValues() length = %d, want %d", len(values), len(expectedValues))
	}

	// Check all values are present (order may vary)
	valueMap := make(map[string]bool)
	for _, v := range values {
		valueMap[v] = true
	}

	for _, expected := range expectedValues {
		if !valueMap[expected] {
			t.Errorf("GetValues() missing value %v", expected)
		}
	}
}

func TestRuleCacheData_Timestamp(t *testing.T) {
	// Initial timestamp
	beforeCreate := time.Now().Unix() - 1
	data := NewRuleCacheData()
	afterCreate := time.Now().Unix() + 1

	if data.Timestamp < beforeCreate || data.Timestamp > afterCreate {
		t.Errorf("Initial Timestamp = %d, should be around current time", data.Timestamp)
	}

	// Timestamp should update on AddRule
	data.AddRule(*NewRuleEntry("192.168.1.1"))
	if data.Timestamp == 0 {
		t.Error("Timestamp should be set after AddRule")
	}

	// Timestamp should update on RemoveRule
	data.RemoveRule("192.168.1.1")
	if data.Timestamp == 0 {
		t.Error("Timestamp should be set after RemoveRule")
	}
}

func TestCacheFileConstants(t *testing.T) {
	if CacheFileBlacklist != "blacklist_cache.bin" {
		t.Errorf("CacheFileBlacklist = %v, want 'blacklist_cache.bin'", CacheFileBlacklist)
	}
	if CacheFileWhitelist != "whitelist_cache.bin" {
		t.Errorf("CacheFileWhitelist = %v, want 'whitelist_cache.bin'", CacheFileWhitelist)
	}
}

func TestRuleEntry_Fields(t *testing.T) {
	entry := RuleEntry{
		Value:   "192.168.1.0/24",
		AddedAt: time.Now(),
		Remark:  "office network",
	}

	if entry.Value != "192.168.1.0/24" {
		t.Errorf("Value = %v, want 192.168.1.0/24", entry.Value)
	}
	if entry.Remark != "office network" {
		t.Errorf("Remark = %v, want 'office network'", entry.Remark)
	}
}
