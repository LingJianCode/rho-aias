package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// IPType IP 地址类型
type IPType uint8

const (
	IPTypeUnknown  IPType = 0
	IPTypeIPv4     IPType = 1
	IPTypeIPV4CIDR IPType = 2
)

func ParseStringToIPType(value string) IPType {
	value = strings.TrimSpace(value)
	_, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		ip := net.ParseIP(value)
		if ip == nil {
			return IPTypeUnknown
		}
		if ip.To4() != nil {
			return IPTypeIPv4
		}
		// 不支持 IPv6，返回 Unknown
		return IPTypeUnknown
	}
	if ipNet.IP.To4() != nil {
		return IPTypeIPV4CIDR
	}
	// 不支持 IPv6 CIDR，返回 Unknown
	return IPTypeUnknown
}

// ip地址为大端，ebpf规定前缀为主机字节序(x86为小端)
func ParseValueToBytes(value string) ([]byte, IPType, error) {
	value = strings.TrimSpace(value)
	// try to parse as CIDR
	_, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		// try to parse as IP
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, IPTypeUnknown, fmt.Errorf("invalid value: %s (only IPv4 or IPv4 CIDR supported)", value)
		}
		if ip.To4() != nil {
			return ip.To4(), IPTypeIPv4, nil
		}
		// 不支持 IPv6
		return nil, IPTypeUnknown, fmt.Errorf("invalid value: %s (only IPv4 or IPv4 CIDR supported)", value)
	}
	ones, _ := ipNet.Mask.Size()
	if ipNet.IP.To4() != nil && len(ipNet.IP) == net.IPv4len {
		var bytes [8]byte
		binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
		copy(bytes[4:], ipNet.IP.To4())
		return bytes[:], IPTypeIPV4CIDR, nil
	}
	// 不支持 IPv6 CIDR
	return nil, IPTypeUnknown, fmt.Errorf("invalid value: %s (only IPv4 or IPv4 CIDR supported)", value)
}


