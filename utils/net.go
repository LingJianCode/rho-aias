package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// IPv4RegexPatternRaw 匹配 IPv4 地址的正则表达式（无边界锚定，用于嵌入其他正则）
const IPv4RegexPatternRaw = `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`

// IPv4RegexPattern 匹配 IPv4 地址的正则表达式（含词边界，用于 FindAllString 提取）
const IPv4RegexPattern = `\b` + IPv4RegexPatternRaw + `\b`

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

// GetLocalIPNets 获取本机所有非回环的 IPv4 地址，返回 /32 CIDR 格式的 net.IPNet 列表
func GetLocalIPNets() ([]*net.IPNet, error) {
	var nets []*net.IPNet

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		// 跳过未启用和 loopback 接口
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// 跳过 loopback 和 IPv6 地址
			if ip == nil || ip.IsLoopback() {
				continue
			}

			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}

			// 创建 /32 CIDR
			ipNet := &net.IPNet{
				IP:   ipv4,
				Mask: net.CIDRMask(32, 32),
			}
			nets = append(nets, ipNet)
		}
	}

	return nets, nil
}


