package ebpfs

import (
	"fmt"
	"net"
	"strings"

	"rho-aias/internal/logger"
)

// ============================================
// Geo-Blocking 相关方法
// ============================================

// UpdateGeoConfig 更新地域封禁配置到内核
func (x *Xdp) UpdateGeoConfig(enabled bool, mode uint32) error {
	config := NewGeoConfig(enabled, mode)
	key := uint32(0)
	return x.objects.GeoConfig.Put(&key, &config)
}

// AddGeoIPRule 添加单条 GeoIP 规则
// 格式: "1.0.0.0/24,CN"
func (x *Xdp) AddGeoIPRule(cidrWithCountry string) error {
	parts := strings.Split(cidrWithCountry, ",")
	if len(parts) < 2 {
		return fmt.Errorf("invalid format, expected: \"cidr,country_code\"")
	}

	cidr := parts[0]
	countryCode := parts[1]

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR failed: %w", err)
	}

	var key IPv4TrieKey
	copy(key.Addr[:], ipNet.IP.To4())
	ones, _ := ipNet.Mask.Size()
	key.PrefixLen = uint32(ones)

	var countryValue uint32
	if len(countryCode) >= 2 {
		countryValue = uint32(countryCode[0])<<24 | uint32(countryCode[1])<<16
	}

	return x.objects.GeoIpv4Whitelist.Put(&key, &countryValue)
}

// BatchAddGeoIPRules 批量添加 GeoIP 规则
func (x *Xdp) BatchAddGeoIPRules(cidrs []string) error {
	keys := make([]IPv4TrieKey, 0, len(cidrs))
	values := make([]uint32, 0, len(cidrs))

	for _, cidrWithCountry := range cidrs {
		parts := strings.Split(cidrWithCountry, ",")
		if len(parts) < 2 {
			logger.Warnf("[GeoBlocking] Invalid format: %s", cidrWithCountry)
			continue
		}

		cidr := parts[0]
		countryCode := parts[1]

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Warnf("[GeoBlocking] Failed to parse CIDR %s: %v", cidr, err)
			continue
		}

		if ipNet.IP.To4() == nil {
			logger.Debugf("[GeoBlocking] Skipping non-IPv4 network: %s", cidr)
			continue
		}

		var key IPv4TrieKey
		copy(key.Addr[:], ipNet.IP.To4())
		ones, _ := ipNet.Mask.Size()
		key.PrefixLen = uint32(ones)

		var countryValue uint32
		if len(countryCode) >= 2 {
			countryValue = uint32(countryCode[0])<<24 | uint32(countryCode[1])<<16
		}

		keys = append(keys, key)
		values = append(values, countryValue)
	}

	for i := range keys {
		if err := x.objects.GeoIpv4Whitelist.Put(&keys[i], &values[i]); err != nil {
			return fmt.Errorf("put GeoIP rule %d failed: %w", i, err)
		}
	}

	return nil
}

// BatchDeleteGeoIPRules 批量删除 GeoIP 规则
func (x *Xdp) BatchDeleteGeoIPRules(cidrs []string) error {
	var errs []error
	for _, cidrWithCountry := range cidrs {
		parts := strings.Split(cidrWithCountry, ",")
		if len(parts) < 1 {
			errs = append(errs, fmt.Errorf("invalid format: %s", cidrWithCountry))
			continue
		}

		cidr := parts[0]

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse CIDR failed: %w", err))
			continue
		}

		var key IPv4TrieKey
		copy(key.Addr[:], ipNet.IP.To4())
		ones, _ := ipNet.Mask.Size()
		key.PrefixLen = uint32(ones)

		if err := x.objects.GeoIpv4Whitelist.Delete(&key); err != nil {
			errs = append(errs, fmt.Errorf("delete %s failed: %w", cidr, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("batch delete failed with %d errors, first: %v", len(errs), errs[0])
	}
	return nil
}

// GetGeoIPRules 获取所有 GeoIP 规则
func (x *Xdp) GetGeoIPRules() ([]string, error) {
	var rules []string
	iter := x.objects.GeoIpv4Whitelist.Iterate()

	var key IPv4TrieKey
	var countryValue uint32

	for iter.Next(&key, &countryValue) {
		ip := net.IP(key.Addr[:])
		cidr := fmt.Sprintf("%s/%d", ip.String(), key.PrefixLen)

		countryCode := ""
		if countryValue != 0 {
			b1 := byte((countryValue >> 24) & 0xFF)
			b2 := byte((countryValue >> 16) & 0xFF)
			countryCode = string([]byte{b1, b2})
		}

		rules = append(rules, fmt.Sprintf("%s,%s", cidr, countryCode))
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate GeoIP rules failed: %w", err)
	}

	return rules, nil
}

// GetGeoConfigEnabled 获取当前 geo_config 的 enabled 状态
func (x *Xdp) GetGeoConfigEnabled() uint32 {
	key := uint32(0)
	config := GeoConfig{}
	if err := x.objects.GeoConfig.Lookup(&key, &config); err != nil {
		return 0
	}
	return config.Enabled
}
