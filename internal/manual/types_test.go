package manual

import (
	"testing"
	"time"
)

func TestNewCacheData(t *testing.T) {
	data := NewCacheData()

	if data == nil {
		t.Fatal("NewCacheData() returned nil")
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

func TestNewManualRuleEntry(t *testing.T) {
	value := "192.168.1.1"
	entry := NewManualRuleEntry(value)

	if entry == nil {
		t.Fatal("NewManualRuleEntry() returned nil")
	}
	if entry.Value != value {
		t.Errorf("Value = %v, want %v", entry.Value, value)
	}
	if entry.Source != SourceManual {
		t.Errorf("Source = %v, want %v", entry.Source, SourceManual)
	}
	if entry.AddedAt.IsZero() {
		t.Error("AddedAt should not be zero")
	}
}

func TestCacheData_AddRule(t *testing.T) {
	data := NewCacheData()

	entry1 := NewManualRuleEntry("192.168.1.1")
	data.AddRule(*entry1)

	if len(data.Rules) != 1 {
		t.Errorf("Rules length = %d, want 1", len(data.Rules))
	}

	// Add same value again (should update)
	entry2 := NewManualRuleEntry("192.168.1.1")
	data.AddRule(*entry2)

	if len(data.Rules) != 1 {
		t.Errorf("Rules length after duplicate = %d, want 1", len(data.Rules))
	}

	// Add different value
	entry3 := NewManualRuleEntry("10.0.0.1")
	data.AddRule(*entry3)

	if len(data.Rules) != 2 {
		t.Errorf("Rules length = %d, want 2", len(data.Rules))
	}
}

func TestCacheData_RemoveRule(t *testing.T) {
	data := NewCacheData()

	// Add some rules
	data.AddRule(*NewManualRuleEntry("192.168.1.1"))
	data.AddRule(*NewManualRuleEntry("10.0.0.1"))
	data.AddRule(*NewManualRuleEntry("172.16.0.1"))

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

func TestCacheData_HasRule(t *testing.T) {
	data := NewCacheData()

	data.AddRule(*NewManualRuleEntry("192.168.1.1"))

	if !data.HasRule("192.168.1.1") {
		t.Error("HasRule() should return true for existing rule")
	}

	if data.HasRule("10.0.0.1") {
		t.Error("HasRule() should return false for non-existing rule")
	}
}

func TestCacheData_RuleCount(t *testing.T) {
	data := NewCacheData()

	if data.RuleCount() != 0 {
		t.Errorf("RuleCount() = %d, want 0", data.RuleCount())
	}

	data.AddRule(*NewManualRuleEntry("192.168.1.1"))
	if data.RuleCount() != 1 {
		t.Errorf("RuleCount() = %d, want 1", data.RuleCount())
	}

	data.AddRule(*NewManualRuleEntry("10.0.0.1"))
	if data.RuleCount() != 2 {
		t.Errorf("RuleCount() = %d, want 2", data.RuleCount())
	}

	data.RemoveRule("192.168.1.1")
	if data.RuleCount() != 1 {
		t.Errorf("RuleCount() = %d, want 1", data.RuleCount())
	}
}

func TestCacheData_GetValues(t *testing.T) {
	data := NewCacheData()

	// Empty data
	values := data.GetValues()
	if len(values) != 0 {
		t.Errorf("GetValues() length = %d, want 0", len(values))
	}

	// Add some rules
	expectedValues := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}
	for _, v := range expectedValues {
		data.AddRule(*NewManualRuleEntry(v))
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

func TestCacheData_Timestamp(t *testing.T) {
	// Initial timestamp
	beforeCreate := time.Now().Unix() - 1
	data := NewCacheData()
	afterCreate := time.Now().Unix() + 1

	if data.Timestamp < beforeCreate || data.Timestamp > afterCreate {
		t.Errorf("Initial Timestamp = %d, should be around current time", data.Timestamp)
	}

	// Timestamp should update on AddRule
	data.AddRule(*NewManualRuleEntry("192.168.1.1"))
	if data.Timestamp == 0 {
		t.Error("Timestamp should be set after AddRule")
	}

	// Timestamp should update on RemoveRule
	data.RemoveRule("192.168.1.1")
	if data.Timestamp == 0 {
		t.Error("Timestamp should be set after RemoveRule")
	}
}

func TestSourceManualConstant(t *testing.T) {
	if SourceManual != "manual" {
		t.Errorf("SourceManual = %v, want 'manual'", SourceManual)
	}
}

func TestManualRuleEntry_Fields(t *testing.T) {
	entry := ManualRuleEntry{
		Value:   "192.168.1.0/24",
		AddedAt: time.Now(),
		Source:  "manual",
	}

	if entry.Value != "192.168.1.0/24" {
		t.Errorf("Value = %v, want 192.168.1.0/24", entry.Value)
	}
	if entry.Source != "manual" {
		t.Errorf("Source = %v, want manual", entry.Source)
	}
}
