package threatintel

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"rho-aias/internal/feed"
)

func TestNewCache(t *testing.T) {
	tempDir := t.TempDir()
	cache := feed.NewCache[CacheData](tempDir, "intel_cache.bin")
	if cache == nil {
		t.Fatal("NewCache() returned nil")
	}
}

func TestCache_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	cache := feed.NewCache[CacheData](tempDir, "intel_cache.bin")

	data := NewCacheData()
	intelData := NewIntelData(SourceIpsum)
	intelData.AddIPv4("192.168.1.1")
	intelData.AddCIDR("10.0.0.0/8")
	data.Sources[SourceIpsum] = *intelData

	if err := cache.Save(*data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.Version != data.Version {
		t.Errorf("Version = %d, want %d", loaded.Version, data.Version)
	}
	if len(loaded.Sources) != 1 {
		t.Errorf("Sources length = %d, want 1", len(loaded.Sources))
	}

	loadedIntel, ok := loaded.Sources[SourceIpsum]
	if !ok {
		t.Fatal("SourceIpsum not found in loaded data")
	}
	if len(loadedIntel.IPv4Exact) != 1 {
		t.Errorf("IPv4Exact length = %d, want 1", len(loadedIntel.IPv4Exact))
	}
	if loadedIntel.IPv4Exact[0] != "192.168.1.1" {
		t.Errorf("IPv4Exact[0] = %v, want 192.168.1.1", loadedIntel.IPv4Exact[0])
	}
	if len(loadedIntel.IPv4CIDR) != 1 {
		t.Errorf("IPv4CIDR length = %d, want 1", len(loadedIntel.IPv4CIDR))
	}
}

func TestCache_Exists(t *testing.T) {
	tempDir := t.TempDir()
	cache := feed.NewCache[CacheData](tempDir, "intel_cache.bin")

	if cache.Exists() {
		t.Error("Exists() should return false for non-existent cache")
	}

	data := NewCacheData()
	if err := cache.Save(*data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if !cache.Exists() {
		t.Error("Exists() should return true after save")
	}
}

func TestCache_Clear(t *testing.T) {
	tempDir := t.TempDir()
	cache := feed.NewCache[CacheData](tempDir, "intel_cache.bin")

	data := NewCacheData()
	if err := cache.Save(*data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := cache.Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if cache.Exists() {
		t.Error("Exists() should return false after clear")
	}
	if err := cache.Clear(); err != nil {
		t.Errorf("Clear() on non-existent file error = %v", err)
	}
}

func TestCache_LoadNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	cache := feed.NewCache[CacheData](tempDir, "intel_cache.bin")

	_, err := cache.Load()
	if err == nil {
		t.Error("Load() should return error for non-existent file")
	}
}

func TestCache_GetModTime(t *testing.T) {
	tempDir := t.TempDir()
	cache := feed.NewCache[CacheData](tempDir, "intel_cache.bin")

	_, err := cache.GetModTime()
	if err == nil {
		t.Error("GetModTime() should return error for non-existent file")
	}

	data := NewCacheData()
	beforeSave := time.Now().Add(-time.Second)
	if err := cache.Save(*data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	modTime, err := cache.GetModTime()
	if err != nil {
		t.Fatalf("GetModTime() error = %v", err)
	}
	if modTime.Before(beforeSave) {
		t.Errorf("ModTime = %v, should be after %v", modTime, beforeSave)
	}
}

func TestCache_MultipleSources(t *testing.T) {
	tempDir := t.TempDir()
	cache := feed.NewCache[CacheData](tempDir, "intel_cache.bin")

	data := NewCacheData()

	ipsumData := NewIntelData(SourceIpsum)
	ipsumData.AddIPv4("1.1.1.1")
	ipsumData.AddIPv4("2.2.2.2")
	data.Sources[SourceIpsum] = *ipsumData

	spamhausData := NewIntelData(SourceSpamhaus)
	spamhausData.AddCIDR("3.3.3.0/24")
	spamhausData.AddCIDR("4.4.4.0/24")
	data.Sources[SourceSpamhaus] = *spamhausData

	if err := cache.Save(*data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(loaded.Sources) != 2 {
		t.Errorf("Sources length = %d, want 2", len(loaded.Sources))
	}

	ipsumLoaded, ok := loaded.Sources[SourceIpsum]
	if !ok {
		t.Fatal("SourceIpsum not found")
	}
	if len(ipsumLoaded.IPv4Exact) != 2 {
		t.Errorf("Ipsum IPv4Exact length = %d, want 2", len(ipsumLoaded.IPv4Exact))
	}

	spamhausLoaded, ok := loaded.Sources[SourceSpamhaus]
	if !ok {
		t.Fatal("SourceSpamhaus not found")
	}
	if len(spamhausLoaded.IPv4CIDR) != 2 {
		t.Errorf("Spamhaus IPv4CIDR length = %d, want 2", len(spamhausLoaded.IPv4CIDR))
	}
}

func TestCache_FilePath(t *testing.T) {
	tempDir := t.TempDir()
	cache := feed.NewCache[CacheData](tempDir, "intel_cache.bin")

	data := NewCacheData()
	if err := cache.Save(*data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	expectedPath := filepath.Join(tempDir, "intel_cache.bin")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("Cache file not found at %s", expectedPath)
	}
}
