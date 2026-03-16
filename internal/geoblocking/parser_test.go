package geoblocking

import (
	"testing"
)

func TestParser_ParseMaxMind(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name             string
		data             string
		allowedCountries []string
		wantCount        int
		wantErr          bool
	}{
		{
			name: "simple data with allowed countries",
			data: `1.0.0.0/24,AU,1397652
2.0.0.0/24,US,1397653
3.0.0.0/24,CN,1397654`,
			allowedCountries: []string{"CN", "US"},
			wantCount:        2, // Only CN and US
			wantErr:          false,
		},
		{
			name: "data with comments",
			data: `# MaxMind GeoIP2
1.0.0.0/24,AU,1397652
# Another comment
2.0.0.0/24,US,1397653`,
			allowedCountries: []string{"US"},
			wantCount:        1,
			wantErr:          false,
		},
		{
			name: "data with empty lines",
			data: `1.0.0.0/24,CN,1397652

2.0.0.0/24,US,1397653

`,
			allowedCountries: []string{"CN", "US"},
			wantCount:        2,
			wantErr:          false,
		},
		{
			name: "no matching countries",
			data: `1.0.0.0/24,AU,1397652
2.0.0.0/24,UK,1397653`,
			allowedCountries: []string{"CN", "US"},
			wantCount:        0,
			wantErr:          false,
		},
		{
			name:             "empty data",
			data:             "",
			allowedCountries: []string{"CN"},
			wantCount:        0,
			wantErr:          false,
		},
		{
			name: "all countries allowed",
			data: `1.0.0.0/24,AU,1397652
2.0.0.0/24,US,1397653
3.0.0.0/24,CN,1397654`,
			allowedCountries: []string{"AU", "US", "CN"},
			wantCount:        3,
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseMaxMind([]byte(tt.data), tt.allowedCountries, SourceMaxMind)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMaxMind() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if result == nil {
					t.Fatal("ParseMaxMind() returned nil result")
				}

				if result.TotalCount() != tt.wantCount {
					t.Errorf("TotalCount = %d, want %d", result.TotalCount(), tt.wantCount)
				}

				if result.Source != SourceMaxMind {
					t.Errorf("Source = %v, want %v", result.Source, SourceMaxMind)
				}
			}
		})
	}
}

func TestParser_ParseDBIP(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name             string
		data             string
		allowedCountries []string
		wantErr          bool
	}{
		{
			name: "simple data",
			data: `1.0.0.0,1.0.0.255,AU
2.0.0.0,2.0.0.255,US
3.0.0.0,3.0.0.255,CN`,
			allowedCountries: []string{"CN"},
			wantErr:          false,
		},
		{
			name: "data with comments",
			data: `# DB-IP GeoIP
1.0.0.0,1.0.0.255,AU
# Comment
2.0.0.0,2.0.0.255,US`,
			allowedCountries: []string{"US"},
			wantErr:          false,
		},
		{
			name:             "empty data",
			data:             "",
			allowedCountries: []string{"CN"},
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.ParseDBIP([]byte(tt.data), tt.allowedCountries, SourceDBIP)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDBIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result == nil {
				t.Error("ParseDBIP() returned nil result")
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
			name:    "maxmind format",
			data:    "1.0.0.0/24,CN,1397652",
			format:  "maxmind",
			wantErr: false,
		},
		{
			name:    "dbip format",
			data:    "1.0.0.0,1.0.0.255,CN",
			format:  "dbip",
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
			result, err := parser.Parse([]byte(tt.data), tt.format, []string{"CN"}, SourceMaxMind)

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

func TestParser_isCountryAllowed(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name             string
		country          string
		allowedCountries []string
		want             bool
	}{
		{
			name:             "country in list",
			country:          "CN",
			allowedCountries: []string{"CN", "US"},
			want:             true,
		},
		{
			name:             "country not in list",
			country:          "JP",
			allowedCountries: []string{"CN", "US"},
			want:             false,
		},
		{
			name:             "empty list",
			country:          "CN",
			allowedCountries: []string{},
			want:             false,
		},
		{
			name:             "nil list",
			country:          "CN",
			allowedCountries: nil,
			want:             false,
		},
		{
			name:             "case sensitive",
			country:          "cn",
			allowedCountries: []string{"CN"},
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parser.isCountryAllowed(tt.country, tt.allowedCountries); got != tt.want {
				t.Errorf("isCountryAllowed() = %v, want %v", got, tt.want)
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
