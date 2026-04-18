package ebpfs

import (
	"testing"
)

func TestNewBlockValue(t *testing.T) {
	tests := []struct {
		name       string
		sourceMask uint32
		want       BlockValue
	}{
		{
			name:       "create block value with ipsum mask",
			sourceMask: SourceMaskIpsum,
			want: BlockValue{
				SourceMask: SourceMaskIpsum,
				Priority:   0,
				Expiry:     0,
			},
		},
		{
			name:       "create block value with manual mask",
			sourceMask: SourceMaskManual,
			want: BlockValue{
				SourceMask: SourceMaskManual,
				Priority:   0,
				Expiry:     0,
			},
		},
		{
			name:       "create block value with combined mask",
			sourceMask: SourceMaskIpsum | SourceMaskManual,
			want: BlockValue{
				SourceMask: SourceMaskIpsum | SourceMaskManual,
				Priority:   0,
				Expiry:     0,
			},
		},
		{
			name:       "create block value with zero mask",
			sourceMask: 0,
			want: BlockValue{
				SourceMask: 0,
				Priority:   0,
				Expiry:     0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBlockValue(tt.sourceMask)
			if got != tt.want {
				t.Errorf("NewBlockValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMaskToSourceIDs(t *testing.T) {
	tests := []struct {
		name string
		mask uint32
		want []string
	}{
		{
			name: "ipsum only",
			mask: SourceMaskIpsum,
			want: []string{"ipsum"},
		},
		{
			name: "spamhaus only",
			mask: SourceMaskSpamhaus,
			want: []string{"spamhaus"},
		},
		{
			name: "manual only",
			mask: SourceMaskManual,
			want: []string{"manual"},
		},
		{
			name: "multiple sources",
			mask: SourceMaskIpsum | SourceMaskManual,
			want: []string{"ipsum", "manual"},
		},
		{
			name: "all sources",
			mask: SourceMaskIpsum | SourceMaskSpamhaus | SourceMaskManual | SourceMaskWAF | SourceMaskDDoS | SourceMaskRateLimit | SourceMaskAnomaly | SourceMaskFailGuard,
			want: []string{"ipsum", "spamhaus", "manual", "waf", "ddos", "rate_limit", "anomaly", "failguard"},
		},
		{
			name: "no sources",
			mask: 0,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskToSourceIDs(tt.mask)
			if len(got) != len(tt.want) {
				t.Errorf("MaskToSourceIDs(%v) returned %d sources, want %d", tt.mask, len(got), len(tt.want))
				return
			}
			for i, source := range got {
				if source != tt.want[i] {
					t.Errorf("MaskToSourceIDs(%v)[%d] = %q, want %q", tt.mask, i, source, tt.want[i])
				}
			}
		})
	}
}

func TestNewGeoConfig(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		mode    uint32
		want    GeoConfig
	}{
		{
			name:    "enabled whitelist",
			enabled: true,
			mode:    0,
			want: GeoConfig{
				Enabled: 1,
				Mode:    0,
				Padding: 0,
			},
		},
		{
			name:    "enabled blacklist",
			enabled: true,
			mode:    1,
			want: GeoConfig{
				Enabled: 1,
				Mode:    1,
				Padding: 0,
			},
		},
		{
			name:    "disabled whitelist",
			enabled: false,
			mode:    0,
			want: GeoConfig{
				Enabled: 0,
				Mode:    0,
				Padding: 0,
			},
		},
		{
			name:    "disabled blacklist",
			enabled: false,
			mode:    1,
			want: GeoConfig{
				Enabled: 0,
				Mode:    1,
				Padding: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewGeoConfig(tt.enabled, tt.mode)
			if got != tt.want {
				t.Errorf("NewGeoConfig(%v, %v) = %v, want %v", tt.enabled, tt.mode, got, tt.want)
			}
		})
	}
}

// ============================================
// Event Config Tests
// ============================================

func TestNewEventConfig(t *testing.T) {
	tests := []struct {
		name       string
		enabled    bool
		sampleRate uint32
		want       BlocklogEventConfig
	}{
		{
			name:       "enabled with default sample rate",
			enabled:    true,
			sampleRate: 1000,
			want: BlocklogEventConfig{
				Enabled:    1,
				SampleRate: 1000,
				Padding:    [2]uint32{0, 0},
			},
		},
		{
			name:       "disabled with custom sample rate",
			enabled:    false,
			sampleRate: 100,
			want: BlocklogEventConfig{
				Enabled:    0,
				SampleRate: 100,
				Padding:    [2]uint32{0, 0},
			},
		},
		{
			name:       "enabled with sample rate 1",
			enabled:    true,
			sampleRate: 1,
			want: BlocklogEventConfig{
				Enabled:    1,
				SampleRate: 1,
				Padding:    [2]uint32{0, 0},
			},
		},
		{
			name:       "zero sample rate defaults to 1000",
			enabled:    true,
			sampleRate: 0,
			want: BlocklogEventConfig{
				Enabled:    1,
				SampleRate: 1000, // 默认采样率
				Padding:    [2]uint32{0, 0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBlocklogEventConfig(tt.enabled, tt.sampleRate)
			if got != tt.want {
				t.Errorf("NewEventConfig(%v, %v) = %v, want %v", tt.enabled, tt.sampleRate, got, tt.want)
			}
		})
	}
}

func TestDefaultEventConfig(t *testing.T) {
	got := DefaultBlocklogEventConfig()
	want := BlocklogEventConfig{
		Enabled:    0,    // 默认关闭
		SampleRate: 1000, // 默认采样率
		Padding:    [2]uint32{0, 0},
	}
	if got != want {
		t.Errorf("DefaultEventConfig() = %v, want %v", got, want)
	}
}
