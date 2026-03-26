package geoblocking

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
	if data.Sources == nil {
		t.Error("Sources map should not be nil")
	}
}

func TestNewGeoIPData(t *testing.T) {
	data := NewGeoIPData(SourceMaxMind)

	if data == nil {
		t.Fatal("NewGeoIPData() returned nil")
	}
	if data.Source != SourceMaxMind {
		t.Errorf("Source = %v, want %v", data.Source, SourceMaxMind)
	}
	if data.IPv4CIDR == nil {
		t.Error("IPv4CIDR slice should not be nil")
	}
	if len(data.IPv4CIDR) != 0 {
		t.Errorf("IPv4CIDR length = %d, want 0", len(data.IPv4CIDR))
	}
	if data.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestGeoIPData_AddCIDR(t *testing.T) {
	data := NewGeoIPData(SourceMaxMind)

	cidrs := []string{"1.0.0.0/24,CN", "2.0.0.0/24,US", "3.0.0.0/24,JP"}
	for _, cidr := range cidrs {
		data.AddCIDR(cidr)
	}

	if len(data.IPv4CIDR) != len(cidrs) {
		t.Errorf("IPv4CIDR length = %d, want %d", len(data.IPv4CIDR), len(cidrs))
	}

	for i, cidr := range cidrs {
		if data.IPv4CIDR[i] != cidr {
			t.Errorf("IPv4CIDR[%d] = %v, want %v", i, data.IPv4CIDR[i], cidr)
		}
	}
}

func TestGeoIPData_AddCIDRs(t *testing.T) {
	data := NewGeoIPData(SourceMaxMind)

	cidrs := []string{"1.0.0.0/24,CN", "2.0.0.0/24,US"}
	data.AddCIDRs(cidrs)

	if len(data.IPv4CIDR) != len(cidrs) {
		t.Errorf("IPv4CIDR length = %d, want %d", len(data.IPv4CIDR), len(cidrs))
	}

	// Add more
	more := []string{"3.0.0.0/24,JP", "4.0.0.0/24,KR"}
	data.AddCIDRs(more)

	if len(data.IPv4CIDR) != 4 {
		t.Errorf("IPv4CIDR length = %d, want 4", len(data.IPv4CIDR))
	}
}

func TestGeoIPData_TotalCount(t *testing.T) {
	data := NewGeoIPData(SourceMaxMind)

	// Empty data
	if data.TotalCount() != 0 {
		t.Errorf("TotalCount() = %d, want 0", data.TotalCount())
	}

	// Add some CIDRs
	data.AddCIDR("1.0.0.0/24,CN")
	data.AddCIDR("2.0.0.0/24,US")
	if data.TotalCount() != 2 {
		t.Errorf("TotalCount() = %d, want 2", data.TotalCount())
	}
}

func TestSourceIDConstants(t *testing.T) {
	if SourceMaxMind != "maxmind" {
		t.Errorf("SourceMaxMind = %v, want 'maxmind'", SourceMaxMind)
	}
	if SourceDBIP != "dbip" {
		t.Errorf("SourceDBIP = %v, want 'dbip'", SourceDBIP)
	}
}

func TestStatus_Struct(t *testing.T) {
	status := Status{
		Enabled:          true,
		Mode:             "whitelist",
		AllowedCountries: []string{"CN", "US"},
		LastUpdate:       time.Now(),
		TotalRules:       100,
		Sources: map[SourceID]SourceStatus{
			SourceMaxMind: {
				Enabled:    true,
				LastUpdate: time.Now(),
				Success:    true,
				RuleCount:  100,
				Error:      "",
			},
		},
	}

	if !status.Enabled {
		t.Error("Status.Enabled should be true")
	}
	if status.Mode != "whitelist" {
		t.Errorf("Status.Mode = %v, want whitelist", status.Mode)
	}
	if status.TotalRules != 100 {
		t.Errorf("Status.TotalRules = %d, want 100", status.TotalRules)
	}
}

func TestSourceStatus_Struct(t *testing.T) {
	ss := SourceStatus{
		Enabled:    true,
		LastUpdate: time.Now(),
		Success:    true,
		RuleCount:  50,
		Error:      "",
	}

	if !ss.Enabled {
		t.Error("SourceStatus.Enabled should be true")
	}
	if !ss.Success {
		t.Error("SourceStatus.Success should be true")
	}
	if ss.RuleCount != 50 {
		t.Errorf("SourceStatus.RuleCount = %d, want 50", ss.RuleCount)
	}
}

func TestErrGeoIPCacheNotFound(t *testing.T) {
	if ErrGeoIPCacheNotFound.Error() != "geoip cache not found" {
		t.Errorf("Error message = %v, want 'geoip cache not found'", ErrGeoIPCacheNotFound)
	}
}

func TestCacheData_Struct(t *testing.T) {
	data := CacheData{
		Version:   1,
		Timestamp: time.Now().Unix(),
		Config: GeoConfig{
			Enabled:          true,
			Mode:             "whitelist",
			AllowedCountries: []string{"CN"},
		},
		Sources: map[SourceID]GeoIPData{
			SourceMaxMind: {
				IPv4CIDR:  []string{"1.0.0.0/24,CN"},
				Timestamp: time.Now(),
				Source:    SourceMaxMind,
			},
		},
	}

	if data.Version != 1 {
		t.Errorf("Version = %d, want 1", data.Version)
	}
	if len(data.Sources) != 1 {
		t.Errorf("Sources length = %d, want 1", len(data.Sources))
	}
}
