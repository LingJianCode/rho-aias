package threatintel

import (
	"testing"
	"time"
)

func TestNewIntelData(t *testing.T) {
	data := NewIntelData(SourceIpsum)

	if data == nil {
		t.Fatal("NewIntelData() returned nil")
	}
	if data.Source != SourceIpsum {
		t.Errorf("Source = %v, want %v", data.Source, SourceIpsum)
	}
	if data.IPv4Exact == nil {
		t.Error("IPv4Exact slice should not be nil")
	}
	if data.IPv4CIDR == nil {
		t.Error("IPv4CIDR slice should not be nil")
	}
	if len(data.IPv4Exact) != 0 {
		t.Errorf("IPv4Exact length = %d, want 0", len(data.IPv4Exact))
	}
}

func TestIntelData_AddIPv4(t *testing.T) {
	data := NewIntelData(SourceIpsum)

	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}
	for _, ip := range ips {
		data.AddIPv4(ip)
	}

	if len(data.IPv4Exact) != len(ips) {
		t.Errorf("IPv4Exact length = %d, want %d", len(data.IPv4Exact), len(ips))
	}

	for i, ip := range ips {
		if data.IPv4Exact[i] != ip {
			t.Errorf("IPv4Exact[%d] = %v, want %v", i, data.IPv4Exact[i], ip)
		}
	}
}

func TestIntelData_AddCIDR(t *testing.T) {
	data := NewIntelData(SourceSpamhaus)

	cidrs := []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"}
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

func TestIntelData_TotalCount(t *testing.T) {
	data := NewIntelData(SourceIpsum)

	// Empty data
	if data.TotalCount() != 0 {
		t.Errorf("TotalCount() = %d, want 0", data.TotalCount())
	}

	// Add some IPs
	data.AddIPv4("192.168.1.1")
	data.AddIPv4("10.0.0.1")
	if data.TotalCount() != 2 {
		t.Errorf("TotalCount() = %d, want 2", data.TotalCount())
	}

	// Add some CIDRs
	data.AddCIDR("172.16.0.0/12")
	data.AddCIDR("192.168.0.0/16")
	if data.TotalCount() != 4 {
		t.Errorf("TotalCount() = %d, want 4", data.TotalCount())
	}
}

func TestSourceIDConstants(t *testing.T) {
	tests := []struct {
		name  string
		value SourceID
		want  string
	}{
		{"ipsum", SourceIpsum, "ipsum"},
		{"spamhaus", SourceSpamhaus, "spamhaus"},
		{"manual", SourceManual, "manual"},
		{"waf", SourceWAF, "waf"},
		{"ddos", SourceDDoS, "ddos"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.value) != tt.want {
				t.Errorf("SourceID = %v, want %v", tt.value, tt.want)
			}
		})
	}
}

func TestStatusStruct(t *testing.T) {
	status := Status{
		Enabled:    true,
		LastUpdate: time.Now(),
		TotalRules: 100,
		Sources: map[SourceID]SourceStatus{
			SourceIpsum: {
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
	if status.TotalRules != 100 {
		t.Errorf("Status.TotalRules = %d, want 100", status.TotalRules)
	}
	if len(status.Sources) != 1 {
		t.Errorf("Status.Sources length = %d, want 1", len(status.Sources))
	}
}

func TestSourceStatusStruct(t *testing.T) {
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
