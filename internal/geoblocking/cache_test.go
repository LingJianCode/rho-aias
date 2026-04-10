package geoblocking

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"rho-aias/internal/source"
)

func TestNewCache(t *testing.T) {
	tempDir := t.TempDir()
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")
	if cache == nil {
		t.Fatal("NewCache() returned nil")
	}
}

func TestCache_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

	data := NewCacheData()
	geoData := NewGeoIPData(SourceMaxMind)
	geoData.AddCIDR("1.0.0.0/24,CN")
	geoData.AddCIDR("2.0.0.0/24,US")
	data.Sources[SourceMaxMind] = *geoData

	err := cache.Save(*data)
	if err != nil {
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
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

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
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

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
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

	_, err := cache.Load()
	if err == nil {
		t.Error("Load() should return error for non-existent file")
	}
}

func TestCache_GetModTime(t *testing.T) {
	tempDir := t.TempDir()
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

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

func TestCache_FilePath(t *testing.T) {
	tempDir := t.TempDir()
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

	data := NewCacheData()
	if err := cache.Save(*data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	expectedPath := filepath.Join(tempDir, "geoip_cache.bin")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("Cache file not found at %s", expectedPath)
	}
}

func TestCache_Overwrite(t *testing.T) {
	tempDir := t.TempDir()
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

	data1 := NewCacheData()
	geoData1 := NewGeoIPData(SourceMaxMind)
	geoData1.AddCIDR("1.0.0.0/24,CN")
	data1.Sources[SourceMaxMind] = *geoData1
	if err := cache.Save(*data1); err != nil {
		t.Fatalf("First Save() error = %v", err)
	}

	data2 := NewCacheData()
	geoData2 := NewGeoIPData(SourceMaxMind)
	geoData2.AddCIDR("2.0.0.0/24,US")
	geoData2.AddCIDR("3.0.0.0/24,JP")
	data2.Sources[SourceMaxMind] = *geoData2
	if err := cache.Save(*data2); err != nil {
		t.Fatalf("Second Save() error = %v", err)
	}

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

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

func TestCache_ConcurrentSave(t *testing.T) {
	tempDir := t.TempDir()
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

	var wg sync.WaitGroup
	errChan := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := NewCacheData()
			geoData := NewGeoIPData(SourceMaxMind)
			geoData.AddCIDR("1.0.0.0/24,CN")
			data.Sources[SourceMaxMind] = *geoData
			if err := cache.Save(*data); err != nil {
				errChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("Concurrent save error: %v", err)
	}

	if !cache.Exists() {
		t.Error("Cache should exist after concurrent saves")
	}

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(loaded.Sources) != 1 {
		t.Errorf("Sources length = %d, want 1", len(loaded.Sources))
	}
}

func TestCache_TmpFileCleanup(t *testing.T) {
	tempDir := t.TempDir()
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

	tmpPath := filepath.Join(tempDir, "geoip_cache.bin.tmp")
	if err := os.WriteFile(tmpPath, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	data := NewCacheData()
	geoData := NewGeoIPData(SourceMaxMind)
	geoData.AddCIDR("1.0.0.0/24,CN")
	data.Sources[SourceMaxMind] = *geoData

	if err := cache.Save(*data); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("Temp file should be cleaned up after successful save")
	}

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(loaded.Sources) != 1 {
		t.Errorf("Sources length = %d, want 1", len(loaded.Sources))
	}
}

func TestCache_NoDataLossOnInterruption(t *testing.T) {
	tempDir := t.TempDir()
	cache := source.NewCache[CacheData](tempDir, "geoip_cache.bin")

	data1 := NewCacheData()
	geoData1 := NewGeoIPData(SourceMaxMind)
	geoData1.AddCIDR("1.0.0.0/24,CN")
	geoData1.AddCIDR("2.0.0.0/24,US")
	data1.Sources[SourceMaxMind] = *geoData1

	if err := cache.Save(*data1); err != nil {
		t.Fatalf("First save error: %v", err)
	}

	loaded1, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	loadedGeo1, ok := loaded1.Sources[SourceMaxMind]
	if !ok {
		t.Fatal("SourceMaxMind not found")
	}
	originalCIDRCount := len(loadedGeo1.IPv4CIDR)

	data2 := NewCacheData()
	geoData2 := NewGeoIPData(SourceMaxMind)
	geoData2.AddCIDR("3.0.0.0/24,JP")
	data2.Sources[SourceMaxMind] = *geoData2

	if err := cache.Save(*data2); err != nil {
		t.Fatalf("Second save error: %v", err)
	}

	loaded2, err := cache.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	loadedGeo2, ok := loaded2.Sources[SourceMaxMind]
	if !ok {
		t.Fatal("SourceMaxMind not found")
	}
	if len(loadedGeo2.IPv4CIDR) == originalCIDRCount {
		t.Error("Data should be updated, not the original")
	}
}
