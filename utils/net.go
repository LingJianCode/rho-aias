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
	IPTypeIPv6     IPType = 3
	IPTypeIPv6CIDR IPType = 4
	IPTypeMAC      IPType = 5
)

func ParseStringToIPType(value string) IPType {
	value = strings.TrimSpace(value)
	_, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		ip := net.ParseIP(value)
		if ip == nil {
			_, err := net.ParseMAC(value)
			if err != nil {
				return IPTypeUnknown
			}
			return IPTypeMAC
		}
		if ip.To4() != nil {
			return IPTypeIPv4
		} else {
			return IPTypeIPv6
		}
	}
	if ipNet.IP.To4() != nil {
		return IPTypeIPV4CIDR
	} else if ipNet.IP.To16() != nil {
		return IPTypeIPv6CIDR
	}
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
			// try to parse as MAC
			macAddr, err := net.ParseMAC(value)
			if err != nil {
				return nil, IPTypeUnknown, fmt.Errorf("invalid value: %s", value)
			}

			return macAddr, IPTypeMAC, nil
		}
		if ip.To4() != nil {
			return ip.To4(), IPTypeIPv4, nil
		} else if ip.To16() != nil {
			return ip.To16(), IPTypeIPv6, nil
		} else {
			return nil, IPTypeUnknown, fmt.Errorf("invalid value: %s", value)
		}
	}
	ones, _ := ipNet.Mask.Size()
	if ipNet.IP.To4() != nil && len(ipNet.IP) == net.IPv4len {
		var bytes [8]byte
		binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
		copy(bytes[4:], ipNet.IP.To4())
		return bytes[:], IPTypeIPV4CIDR, nil
	} else if ipNet.IP.To16() != nil && len(ipNet.IP) == net.IPv6len {
		var bytes [20]byte
		binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
		copy(bytes[4:], ipNet.IP.To16())
		return bytes[:], IPTypeIPv6CIDR, nil
	} else {
		return nil, IPTypeUnknown, fmt.Errorf("invalid value: %s", value)
	}
}


