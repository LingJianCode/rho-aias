package utils

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestIsLocalIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"local IP 127.0.0.1", "127.0.0.1", true},
		{"local IP 192.168.1.1", "192.168.1.1", true},
		{"public IP 8.8.8.8", "8.8.8.8", false},
		{"invalid IP invalid", "invalid", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLocalIP(tt.ip); got != tt.expected {
				t.Errorf("IsLocalIP() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetDefaultInterface(t *testing.T) {
	result := GetDefaultInterface()
	if result == "" {
		t.Error("GetDefaultInterface() return empty string")
	}
	if !ValidateInterface(result) {
		t.Errorf("GetDefaultInterface() returned invalid interface: %s", result)
	}
}

func TestValidateInterface(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("cannot get network interfaces for test")
	}
	validIface := ifaces[0].Name

	tests := []struct {
		name     string
		iface    string
		expected bool
	}{
		{"valid interface", validIface, true},
		{"invalid interface", "invalid_interface", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateInterface(tt.iface); got != tt.expected {
				t.Errorf("ValidateInterface() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsValidMAC(t *testing.T) {
	tests := []struct {
		name     string
		mac      string
		expected bool
	}{
		{"valid MAC", "00:00:5e:00:53:01", true},
		{"invalid MAC", "00:00:5e:00:53", false},
		{"lowercase MAC", "aa:bb:cc:dd:ee:ff", true},
		{"uppercase MAC", "AA:BB:CC:DD:EE:FF", true},
		{"mixed case MAC", "aA:bB:cC:dD:eE:fF", true},
		{"invalid characters", "gg:00:5e:00:53:01", false},
		{"dash format", "00-00-5e-00-53-01", true},
		{"invalid format", "invalid", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidMAC(tt.mac); got != tt.expected {
				t.Errorf("IsValidMAC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsValidIPv4(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"valid IPv4", "192.168.1.1", true},
		{"invalid IPv4", "256.256.256.256", false},
		{"IPv6 address", "2001:db8::1", false},
		{"invalid format", "invalid", false},
		{"empty string", "", false},
		{"leading zeros", "192.168.001.001", false},
		{"missing octet", "192.168.1", false},
		{"extra octet", "192.168.1.1.1", false},
		{"negative number", "-1.2.3.4", false},
		{"with spaces", "192.168.1.1 ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIPv4(tt.ip); got != tt.expected {
				t.Errorf("IsValidIPv4() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsValidIPv6(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"valid IPv6", "2001:db8::1", true},
		{"IPv4 address", "192.168.1.1", false},
		{"invalid format", "invalid", false},
		{"empty string", "", false},
		{"compressed zeros", "::", true},
		{"full address", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
		{"mixed notation", "::ffff:192.168.1.1", false},
		{"too many segments", "2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234", false},
		{"invalid characters", "2001:0db8:85a3:0000:0000:8a2g:0370:7334", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIPv6(tt.ip); got != tt.expected {
				t.Errorf("IsValidIPv6() = %v, want %v", got, tt.expected)
			}
		})
	}
}

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
		{name: "IPv4 with spaces", input: " 192.168.1.1 ", wantBytes: []byte{192, 168, 1, 1}, wantIPType: IPTypeIPv4, wantErr: false},
		{name: "IPv4 with invalid segment", input: "192.168.1.300", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv4 with negative segment", input: "192.168.-1.1", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Valid IPv6", input: "2001:db8::1", wantBytes: net.ParseIP("2001:db8::1").To16(), wantIPType: IPTypeIPv6, wantErr: false},
		{name: "IPv6 full format", input: "2001:0db8:0000:0000:0000:8a2e:0370:7334", wantBytes: net.ParseIP("2001:0db8:0000:0000:0000:8a2e:0370:7334").To16(), wantIPType: IPTypeIPv6, wantErr: false},
		{name: "IPv6 compressed zeros", input: "::", wantBytes: net.ParseIP("::").To16(), wantIPType: IPTypeIPv6, wantErr: false},
		{name: "IPv4 CIDR minimum prefix", input: "0.0.0.0/0", wantBytes: createIPv4CIDRBytes(0, []byte{0, 0, 0, 0}), wantIPType: IPTypeIPV4CIDR, wantErr: false},
		{name: "IPv4 CIDR maximum prefix", input: "192.168.1.1/32", wantBytes: createIPv4CIDRBytes(32, []byte{192, 168, 1, 1}), wantIPType: IPTypeIPV4CIDR, wantErr: false},
		{name: "IPv4 CIDR with invalid prefix", input: "192.168.1.0/-1", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Valid IPv4 CIDR", input: "192.168.1.0/24", wantBytes: createIPv4CIDRBytes(24, []byte{192, 168, 1, 0}), wantIPType: IPTypeIPV4CIDR, wantErr: false},
		{name: "Valid IPv6 CIDR", input: "2001:db8::/32", wantBytes: createIPv6CIDRBytes(32, net.ParseIP("2001:db8::").To16()), wantIPType: IPTypeIPv6CIDR, wantErr: false},
		{name: "IPv6 CIDR minimum prefix", input: "::/0", wantBytes: createIPv6CIDRBytes(0, net.ParseIP("::").To16()), wantIPType: IPTypeIPv6CIDR, wantErr: false},
		{name: "IPv6 CIDR maximum prefix", input: "2001:db8::1/128", wantBytes: createIPv6CIDRBytes(128, net.ParseIP("2001:db8::1").To16()), wantIPType: IPTypeIPv6CIDR, wantErr: false},
		{name: "IPv6 CIDR with invalid prefix", input: "2001:db8::/129", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Valid MAC address", input: "00:11:22:33:44:55", wantBytes: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, wantIPType: IPTypeMAC, wantErr: false},
		{name: "MAC address with hyphens", input: "00-11-22-33-44-55", wantBytes: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, wantIPType: IPTypeMAC, wantErr: false},
		{name: "MAC address uppercase", input: "AA:BB:CC:DD:EE:FF", wantBytes: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, wantIPType: IPTypeMAC, wantErr: false},
		{name: "MAC address mixed case", input: "aA:bB:cC:dD:eE:fF", wantBytes: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, wantIPType: IPTypeMAC, wantErr: false},
		{name: "MAC address with invalid characters", input: "GG:HH:II:JJ:KK:LL", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "MAC address too short", input: "00:11:22:33:44", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "MAC address too long", input: "00:11:22:33:44:55:66", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Invalid IP", input: "256.256.256.256", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Invalid CIDR", input: "192.168.1.0/33", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Invalid MAC", input: "00:11:22:33:44:ZZ", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Empty string", input: "", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Empty string with spaces", input: " ", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Empty string with tabs", input: "\t\n\r", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Control characters", input: "192.168.1.1\n", wantBytes: []byte{192, 168, 1, 1}, wantIPType: IPTypeIPv4, wantErr: false},
		{name: "Unicode input", input: "192.168.1.1。", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "Very long input", input: strings.Repeat("a", 1000), wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv4 with leading zeros", input: "192.168.001.001", wantBytes: nil, wantIPType: IPTypeUnknown, wantErr: true},
		{name: "IPv4 CIDR with small prefix", input: "10.0.0.0/8", wantBytes: createIPv4CIDRBytes(8, []byte{10, 0, 0, 0}), wantIPType: IPTypeIPV4CIDR, wantErr: false},
		{name: "IPv6 CIDR with large prefix", input: "2001:db8::/120", wantBytes: createIPv6CIDRBytes(120, net.ParseIP("2001:db8::").To16()), wantIPType: IPTypeIPv6CIDR, wantErr: false},
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

func createIPv6CIDRBytes(ones int, ip []byte) []byte {
	var bytes [20]byte
	binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
	copy(bytes[4:], ip)
	return bytes[:]
}
