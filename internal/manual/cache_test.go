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
	data := NewRuleCacheData()
	data.AddRule(*NewRuleEntry("192.168.1.1"))
	data.AddRule(*NewRuleEntry("10.0.0.1"))
	data.AddRule(*NewRuleEntry("172.16.0.0/12"))

	// Save
	err := cache.SaveData(data, CacheFileBlacklist)
	if err != nil {
		t.Fatalf("SaveData() error = %v", err)
	}

	// Load
	loaded, err := cache.LoadData(CacheFileBlacklist)
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
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

func TestCache_DataExists(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Should not exist initially
	if cache.DataExists(CacheFileBlacklist) {
		t.Error("DataExists() should return false for non-existent cache")
	}

	// Save data
	data := NewRuleCacheData()
	if err := cache.SaveData(data, CacheFileBlacklist); err != nil {
		t.Fatalf("SaveData() error = %v", err)
	}

	// Should exist now
	if !cache.DataExists(CacheFileBlacklist) {
		t.Error("DataExists() should return true after save")
	}
}

func TestCache_ClearData(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Save data
	data := NewRuleCacheData()
	if err := cache.SaveData(data, CacheFileBlacklist); err != nil {
		t.Fatalf("SaveData() error = %v", err)
	}

	// Clear
	if err := cache.ClearData(CacheFileBlacklist); err != nil {
		t.Fatalf("ClearData() error = %v", err)
	}

	// Should not exist
	if cache.DataExists(CacheFileBlacklist) {
		t.Error("DataExists() should return false after clear")
	}

	// Clear again (should not error on non-existent file)
	if err := cache.ClearData(CacheFileBlacklist); err != nil {
		t.Errorf("ClearData() on non-existent file error = %v", err)
	}
}

func TestCache_LoadNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	_, err := cache.LoadData(CacheFileBlacklist)
	if err == nil {
		t.Error("LoadData() should return error for non-existent file")
	}
}

func TestCache_GetModTime(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Non-existent file
	_, err := cache.GetModTime(CacheFileBlacklist)
	if err == nil {
		t.Error("GetModTime() should return error for non-existent file")
	}

	// Save data
	data := NewRuleCacheData()
	beforeSave := time.Now().Add(-time.Second)
	if err := cache.SaveData(data, CacheFileBlacklist); err != nil {
		t.Fatalf("SaveData() error = %v", err)
	}

	// Get modification time
	modTime, err := cache.GetModTime(CacheFileBlacklist)
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
	data := NewRuleCacheData()

	rules := []string{
		"192.168.1.1", // IPv4 exact
		"10.0.0.0/8",  // IPv4 CIDR
	}

	for _, rule := range rules {
		data.AddRule(*NewRuleEntry(rule))
	}

	// Save
	if err := cache.SaveData(data, CacheFileBlacklist); err != nil {
		t.Fatalf("SaveData() error = %v", err)
	}

	// Load
	loaded, err := cache.LoadData(CacheFileBlacklist)
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
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

	// Save blocklist data
	data := NewRuleCacheData()
	if err := cache.SaveData(data, CacheFileBlacklist); err != nil {
		t.Fatalf("SaveData() error = %v", err)
	}

	// Verify file exists at expected path
	expectedPath := filepath.Join(tempDir, CacheFileBlacklist)
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("Cache file not found at %s", expectedPath)
	}

	// Save whitelist data
	if err := cache.SaveData(data, CacheFileWhitelist); err != nil {
		t.Fatalf("SaveData() error = %v", err)
	}

	expectedPath = filepath.Join(tempDir, CacheFileWhitelist)
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("Cache file not found at %s", expectedPath)
	}
}

func TestCache_Overwrite(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Save initial data
	data1 := NewRuleCacheData()
	data1.AddRule(*NewRuleEntry("192.168.1.1"))
	if err := cache.SaveData(data1, CacheFileBlacklist); err != nil {
		t.Fatalf("First SaveData() error = %v", err)
	}

	// Save new data
	data2 := NewRuleCacheData()
	data2.AddRule(*NewRuleEntry("10.0.0.1"))
	data2.AddRule(*NewRuleEntry("172.16.0.1"))
	if err := cache.SaveData(data2, CacheFileBlacklist); err != nil {
		t.Fatalf("Second SaveData() error = %v", err)
	}

	// Load and verify
	loaded, err := cache.LoadData(CacheFileBlacklist)
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
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

func TestCache_WhitelistRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	data := NewRuleCacheData()
	data.AddRule(*NewRuleEntry("1.2.3.4"))
	data.AddRule(*NewRuleEntry("10.0.0.0/8"))

	if err := cache.SaveData(data, CacheFileWhitelist); err != nil {
		t.Fatalf("SaveData() error = %v", err)
	}

	loaded, err := cache.LoadData(CacheFileWhitelist)
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}

	if loaded.RuleCount() != 2 {
		t.Errorf("RuleCount = %d, want 2", loaded.RuleCount())
	}

	if !loaded.HasRule("1.2.3.4") {
		t.Error("Missing rule 1.2.3.4")
	}
}
