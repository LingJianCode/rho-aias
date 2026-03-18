package geoblocking

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
	geoData := NewGeoIPData(SourceMaxMind)
	geoData.AddCIDR("1.0.0.0/24,CN")
	geoData.AddCIDR("2.0.0.0/24,US")
	data.Sources[SourceMaxMind] = *geoData

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

	if len(loaded.Sources) != 1 {
		t.Errorf("Sources length = %d, want 1", len(loaded.Sources))
	}

	loadedGeo, ok := loaded.Sources[SourceMaxMind]
	if !ok {
		t.Fatal("SourceMaxMind not found in loaded data")
	}

	if len(loadedGeo.IPv4CIDR) != 2 {
		t.Errorf("IPv4CIDR length = %d, want 2", len(loadedGeo.IPv4CIDR))
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

	// Clear again (should not error)
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

func TestCache_FilePath(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Save data
	data := NewCacheData()
	if err := cache.Save(data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify file exists at expected path
	expectedPath := filepath.Join(tempDir, "geoip_cache.bin")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("Cache file not found at %s", expectedPath)
	}
}

func TestCache_Overwrite(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewCache(tempDir)

	// Save initial data
	data1 := NewCacheData()
	geoData1 := NewGeoIPData(SourceMaxMind)
	geoData1.AddCIDR("1.0.0.0/24,CN")
	data1.Sources[SourceMaxMind] = *geoData1
	if err := cache.Save(data1); err != nil {
		t.Fatalf("First Save() error = %v", err)
	}

	// Save new data
	data2 := NewCacheData()
	geoData2 := NewGeoIPData(SourceMaxMind)
	geoData2.AddCIDR("2.0.0.0/24,US")
	geoData2.AddCIDR("3.0.0.0/24,JP")
	data2.Sources[SourceMaxMind] = *geoData2
	if err := cache.Save(data2); err != nil {
		t.Fatalf("Second Save() error = %v", err)
	}

	// Load and verify
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Should have new data
	loadedGeo, ok := loaded.Sources[SourceMaxMind]
	if !ok {
		t.Fatal("SourceMaxMind not found in loaded data")
	}

	if len(loadedGeo.IPv4CIDR) != 2 {
		t.Errorf("IPv4CIDR length = %d, want 2", len(loadedGeo.IPv4CIDR))
	}

	if loadedGeo.IPv4CIDR[0] != "2.0.0.0/24,US" {
		t.Errorf("IPv4CIDR[0] = %v, want 2.0.0.0/24,US", loadedGeo.IPv4CIDR[0])
	}
}
