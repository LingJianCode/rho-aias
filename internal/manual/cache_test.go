package manual

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCache(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	if cache == nil {
		t.Fatal("NewCache() returned nil")
	}
	if cache.dir != tempDir {
		t.Errorf("cache.dir = %v, want %v", cache.dir, tempDir)
	}
}

func TestCache_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Create test data
	data := NewCacheData()
	data.AddRule(*NewManualRuleEntry("192.168.1.1"))
	data.AddRule(*NewManualRuleEntry("10.0.0.1"))
	data.AddRule(*NewManualRuleEntry("172.16.0.0/12"))

	// Save
	err := cache.Save(data)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Load
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify
	if loaded.Version != data.Version {
		t.Errorf("Version = %d, want %d", loaded.Version, data.Version)
	}

	if loaded.RuleCount() != 3 {
		t.Errorf("RuleCount = %d, want 3", loaded.RuleCount())
	}

	if !loaded.HasRule("192.168.1.1") {
		t.Error("Loaded data missing rule 192.168.1.1")
	}

	if !loaded.HasRule("10.0.0.1") {
		t.Error("Loaded data missing rule 10.0.0.1")
	}

	if !loaded.HasRule("172.16.0.0/12") {
		t.Error("Loaded data missing rule 172.16.0.0/12")
	}
}

func TestCache_Exists(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Should not exist initially
	if cache.Exists() {
		t.Error("Exists() should return false for non-existent cache")
	}

	// Save data
	data := NewCacheData()
	if err := cache.Save(data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Should exist now
	if !cache.Exists() {
		t.Error("Exists() should return true after save")
	}
}

func TestCache_Clear(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Save data
	data := NewCacheData()
	if err := cache.Save(data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Clear
	if err := cache.Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	// Should not exist
	if cache.Exists() {
		t.Error("Exists() should return false after clear")
	}

	// Clear again (should not error on non-existent file)
	if err := cache.Clear(); err != nil {
		t.Errorf("Clear() on non-existent file error = %v", err)
	}
}

func TestCache_LoadNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	_, err := cache.Load()
	if err == nil {
		t.Error("Load() should return error for non-existent file")
	}
}

func TestCache_GetModTime(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Non-existent file
	_, err := cache.GetModTime()
	if err == nil {
		t.Error("GetModTime() should return error for non-existent file")
	}

	// Save data
	data := NewCacheData()
	beforeSave := time.Now().Add(-time.Second)
	if err := cache.Save(data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Get modification time
	modTime, err := cache.GetModTime()
	if err != nil {
		t.Fatalf("GetModTime() error = %v", err)
	}

	if modTime.Before(beforeSave) {
		t.Errorf("ModTime = %v, should be after %v", modTime, beforeSave)
	}
}

func TestCache_RoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Create data with multiple rules of different types
	data := NewCacheData()

	rules := []string{
		"192.168.1.1",      // IPv4 exact
		"10.0.0.0/8",       // IPv4 CIDR
		"2001:db8::1",      // IPv6 exact
		"2001:db8::/32",    // IPv6 CIDR
		"00:11:22:33:44:55", // MAC
	}

	for _, rule := range rules {
		data.AddRule(*NewManualRuleEntry(rule))
	}

	// Save
	if err := cache.Save(data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Load
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify all rules
	if loaded.RuleCount() != len(rules) {
		t.Errorf("RuleCount = %d, want %d", loaded.RuleCount(), len(rules))
	}

	for _, rule := range rules {
		if !loaded.HasRule(rule) {
			t.Errorf("Missing rule: %v", rule)
		}
	}
}

func TestCache_FilePath(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Save data
	data := NewCacheData()
	if err := cache.Save(data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify file exists at expected path
	expectedPath := filepath.Join(tempDir, "manual_cache.bin")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("Cache file not found at %s", expectedPath)
	}
}

func TestCache_Overwrite(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Save initial data
	data1 := NewCacheData()
	data1.AddRule(*NewManualRuleEntry("192.168.1.1"))
	if err := cache.Save(data1); err != nil {
		t.Fatalf("First Save() error = %v", err)
	}

	// Save new data
	data2 := NewCacheData()
	data2.AddRule(*NewManualRuleEntry("10.0.0.1"))
	data2.AddRule(*NewManualRuleEntry("172.16.0.1"))
	if err := cache.Save(data2); err != nil {
		t.Fatalf("Second Save() error = %v", err)
	}

	// Load and verify
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Should have new data
	if loaded.HasRule("192.168.1.1") {
		t.Error("Should not have old rule 192.168.1.1")
	}

	if !loaded.HasRule("10.0.0.1") {
		t.Error("Should have new rule 10.0.0.1")
	}

	if !loaded.HasRule("172.16.0.1") {
		t.Error("Should have new rule 172.16.0.1")
	}
}
