package threatintel

import (
	"testing"
)

func TestParser_ParseIpsum(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name         string
		data         string
		wantExact    int
		wantCIDR     int
		wantTotal    int
		wantErr      bool
	}{
		{
			name: "simple IPs",
			data: `5.187.35.21     11
31.59.129.85    10
45.155.205.233  9`,
			wantExact: 3,
			wantCIDR:  0,
			wantTotal: 3,
			wantErr:   false,
		},
		{
			name: "with comments",
			data: `# IPsum Threat Intelligence Feed
5.187.35.21     11
# Another comment
31.59.129.85    10`,
			wantExact: 2,
			wantCIDR:  0,
			wantTotal: 2,
			wantErr:   false,
		},
		{
			name: "with empty lines",
			data: `5.187.35.21     11

31.59.129.85    10

`,
			wantExact: 2,
			wantCIDR:  0,
			wantTotal: 2,
			wantErr:   false,
		},
		{
			name: "with CIDR",
			data: `192.168.1.0/24  5
10.0.0.0/8      3
172.16.0.0/12   2`,
			wantExact: 0,
			wantCIDR:  3,
			wantTotal: 3,
			wantErr:   false,
		},
		{
			name: "mixed IPs and CIDRs",
			data: `5.187.35.21     11
192.168.1.0/24  5
31.59.129.85    10
10.0.0.0/8      3`,
			wantExact: 2,
			wantCIDR:  2,
			wantTotal: 4,
			wantErr:   false,
		},
		{
			name:      "empty data",
			data:      "",
			wantExact: 0,
			wantCIDR:  0,
			wantTotal: 0,
			wantErr:   false,
		},
		{
			name: "only comments",
			data: `# Comment 1
# Comment 2`,
			wantExact: 0,
			wantCIDR:  0,
			wantTotal: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseIpsum([]byte(tt.data), SourceIpsum)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIpsum() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if result == nil {
					t.Fatal("ParseIpsum() returned nil result")
				}

				if len(result.IPv4Exact) != tt.wantExact {
					t.Errorf("IPv4Exact count = %d, want %d", len(result.IPv4Exact), tt.wantExact)
				}

				if len(result.IPv4CIDR) != tt.wantCIDR {
					t.Errorf("IPv4CIDR count = %d, want %d", len(result.IPv4CIDR), tt.wantCIDR)
				}

				if result.TotalCount() != tt.wantTotal {
					t.Errorf("TotalCount = %d, want %d", result.TotalCount(), tt.wantTotal)
				}

				if result.Source != SourceIpsum {
					t.Errorf("Source = %v, want %v", result.Source, SourceIpsum)
				}
			}
		})
	}
}

func TestParser_ParseSpamhaus(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name         string
		data         string
		wantExact    int
		wantCIDR     int
		wantTotal    int
		wantErr      bool
	}{
		{
			name: "simple CIDRs",
			data: `1.10.16.0/20 ; SBL256894
1.19.0.0/16 ; SBL434604
2.57.122.0/24 ; SBL636050`,
			wantExact: 0,
			wantCIDR:  3,
			wantTotal: 3,
			wantErr:   false,
		},
		{
			name: "with comments",
			data: `; Spamhaus DROP List
1.10.16.0/20 ; SBL256894
; Another comment
1.19.0.0/16 ; SBL434604`,
			wantExact: 0,
			wantCIDR:  2,
			wantTotal: 2,
			wantErr:   false,
		},
		{
			name: "with empty lines",
			data: `1.10.16.0/20 ; SBL256894

1.19.0.0/16 ; SBL434604

`,
			wantExact: 0,
			wantCIDR:  2,
			wantTotal: 2,
			wantErr:   false,
		},
		{
			name: "with single IPs",
			data: `192.168.1.1 ; Test1
10.0.0.1 ; Test2`,
			wantExact: 2,
			wantCIDR:  0,
			wantTotal: 2,
			wantErr:   false,
		},
		{
			name: "mixed",
			data: `1.10.16.0/20 ; SBL256894
192.168.1.1 ; Test
1.19.0.0/16 ; SBL434604`,
			wantExact: 1,
			wantCIDR:  2,
			wantTotal: 3,
			wantErr:   false,
		},
		{
			name:      "empty data",
			data:      "",
			wantExact: 0,
			wantCIDR:  0,
			wantTotal: 0,
			wantErr:   false,
		},
		{
			name: "only comments",
			data: `; Comment 1
; Comment 2`,
			wantExact: 0,
			wantCIDR:  0,
			wantTotal: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseSpamhaus([]byte(tt.data), SourceSpamhaus)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSpamhaus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if result == nil {
					t.Fatal("ParseSpamhaus() returned nil result")
				}

				if len(result.IPv4Exact) != tt.wantExact {
					t.Errorf("IPv4Exact count = %d, want %d", len(result.IPv4Exact), tt.wantExact)
				}

				if len(result.IPv4CIDR) != tt.wantCIDR {
					t.Errorf("IPv4CIDR count = %d, want %d", len(result.IPv4CIDR), tt.wantCIDR)
				}

				if result.TotalCount() != tt.wantTotal {
					t.Errorf("TotalCount = %d, want %d", result.TotalCount(), tt.wantTotal)
				}

				if result.Source != SourceSpamhaus {
					t.Errorf("Source = %v, want %v", result.Source, SourceSpamhaus)
				}
			}
		})
	}
}

func TestParser_Parse(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name    string
		data    string
		format  string
		wantErr bool
	}{
		{
			name:    "ipsum format",
			data:    "5.187.35.21     11",
			format:  "ipsum",
			wantErr: false,
		},
		{
			name:    "spamhaus format",
			data:    "1.10.16.0/20 ; SBL256894",
			format:  "spamhaus",
			wantErr: false,
		},
		{
			name:    "unsupported format",
			data:    "some data",
			format:  "unknown",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.Parse([]byte(tt.data), tt.format, SourceIpsum)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result == nil {
				t.Error("Parse() returned nil result without error")
			}
		})
	}
}

func TestNewParser(t *testing.T) {
	parser := NewParser()
	if parser == nil {
		t.Error("NewParser() returned nil")
	}
}
