package utils

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseValueToBytes(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantBytes  []byte
		wantIPType IPType
		wantErr    bool
	}{
		{name: "Valid IPv4", input: "192.168.1.1", wantBytes: []byte{192, 168, 1, 1}, wantIPType: IPTypeIPv4, wantErr: false},
		{name: "IPv4 with all zeros", input: "0.0.0.0", wantBytes: []byte{0, 0, 0, 0}, wantIPType: IPTypeIPv4, wantErr: false},
		{name: "IPv4 with all 255", input: "255.255.255.255", wantBytes: []byte{255, 255, 255, 255}, wantIPType: IPTypeIPv4, wantErr: false},
		{name: "Valid IPv4 with spaces", input: " 192.168.1.1 ", wantBytes: []byte{192, 168, 1, 1}, wantIPType: IPTypeIPv4, wantErr: false},
		{name: "IPv4 with invalid segment", input: "192.168.1.300", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv4 with negative segment", input: "192.168.-1.1", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv6 not supported", input: "2001:db8::1", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv6 compressed zeros not supported", input: "::", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv4 CIDR minimum prefix", input: "0.0.0.0/0", wantBytes: createIPv4CIDRBytes(0, []byte{0, 0, 0, 0}), wantIPType: IPTypeIPV4CIDR, wantErr: false},
		{name: "IPv4 CIDR maximum prefix", input: "192.168.1.1/32", wantBytes: createIPv4CIDRBytes(32, []byte{192, 168, 1, 1}), wantIPType: IPTypeIPV4CIDR, wantErr: false},
		{name: "IPv4 CIDR with invalid prefix", input: "192.168.1.0/-1", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Valid IPv4 CIDR", input: "192.168.1.0/24", wantBytes: createIPv4CIDRBytes(24, []byte{192, 168, 1, 0}), wantIPType: IPTypeIPV4CIDR, wantErr: false},
		{name: "IPv6 CIDR not supported", input: "2001:db8::/32", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv6 CIDR not supported 2", input: "::/0", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv6 CIDR not supported 3", input: "2001:db8::1/128", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv6 CIDR invalid prefix not supported", input: "2001:db8::/129", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Valid MAC address", input: "00:11:22:33:44:55", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "MAC address with hyphens", input: "00-11-22-33-44-55", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "MAC address uppercase", input: "AA:BB:CC:DD:EE:FF", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "MAC address mixed case", input: "aA:bB:cC:dD:eE:fF", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "MAC address with invalid characters", input: "GG:HH:II:JJ:KK:LL", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "MAC address too short", input: "00:11:22:33:44", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "MAC address too long", input: "00:11:22:33:44:55:66", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Invalid IP", input: "256.256.256.256", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Invalid CIDR", input: "192.168.1.0/33", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Invalid string", input: "00:11:22:33:44:ZZ", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Empty string", input: "", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Empty string with spaces", input: " ", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Empty string with tabs", input: "\t\n\r", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Control characters", input: "192.168.1.1\n", wantBytes: []byte{192, 168, 1, 1}, wantIPType: IPTypeIPv4, wantErr: false},
		{name: "Unicode input", input: "192.168.1.1。", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Very long input", input: strings.Repeat("a", 1000), wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv4 with leading zeros", input: "192.168.001.001", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv4 CIDR with small prefix", input: "10.0.0.0/8", wantBytes: createIPv4CIDRBytes(8, []byte{10, 0, 0, 0}), wantIPType: IPTypeIPV4CIDR, wantErr: false},
		{name: "IPv6 CIDR not supported 4", input: "2001:db8::/120", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, gotIPType, err := ParseValueToBytes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseValueToBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if gotIPType != tt.wantIPType {
				t.Errorf("ParseValueToBytes() gotIPType = %v, want %v", gotIPType, tt.wantIPType)
			}
			if !bytes.Equal(gotBytes, tt.wantBytes) {
				t.Errorf("ParseValueToBytes() gotBytes = %v, want %v", gotBytes, tt.wantBytes)
			}
		})
	}
}

func createIPv4CIDRBytes(ones int, ip []byte) []byte {
	var bytes [8]byte
	binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
	copy(bytes[4:], ip)
	return bytes[:]
}
