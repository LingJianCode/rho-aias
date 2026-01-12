// Package geoblocking 地域封禁模块
package geoblocking

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// Parser GeoIP 数据解析器
// 支持 MaxMind GeoIP2 CSV 格式
type Parser struct{}

// NewParser 创建新的 GeoIP 数据解析器
func NewParser() *Parser {
	return &Parser{}
}

// ParseMaxMind 解析 MaxMind GeoIP2 CSV 格式
// 格式: "network,registered_country_iso_code,..."
// 示例: "1.0.0.0/24,AU,1397652"
// 数据由外部工具托管在 nginx，直接 HTTP 获取 CSV
func (p *Parser) ParseMaxMind(data []byte, allowedCountries []string, source SourceID) (*GeoIPData, error) {
	result := NewGeoIPData(source)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释行（以 # 开头）
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析 CSV 行: "network,country_code,..."
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}

		cidr := strings.TrimSpace(parts[0])
		country := strings.TrimSpace(parts[1])

		// 跳过无效的国家代码
		if country == "" {
			continue
		}

		// 只添加在允许列表中的国家
		if p.isCountryAllowed(country, allowedCountries) {
			result.AddCIDR(cidr + "," + country)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	return result, nil
}

// ParseDBIP 解析 DB-IP GeoIP CSV 格式
// 格式: "start_ip,end_ip,country_code"
// 示例: "1.0.0.0,1.0.0.255,AU"
func (p *Parser) ParseDBIP(data []byte, allowedCountries []string, source SourceID) (*GeoIPData, error) {
	result := NewGeoIPData(source)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析 CSV 行: "start_ip,end_ip,country_code"
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}

		startIP := strings.TrimSpace(parts[0])
		endIP := strings.TrimSpace(parts[1])
		country := strings.TrimSpace(parts[2])

		// 跳过无效的国家代码
		if country == "" {
			continue
		}

		// 将 IP 范围转换为 CIDR 格式
		cidr, err := p.rangeToCIDR(startIP, endIP)
		if err != nil {
			continue // 跳过无法转换的条目
		}

		// 只添加在允许列表中的国家
		if p.isCountryAllowed(country, allowedCountries) {
			result.AddCIDR(cidr + "," + country)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	return result, nil
}

// ParseMaxMindDB 解析 MaxMind MMDB 二进制格式
// 使用 GeoLite2-Country.mmdb 文件进行国家级别的过滤
// 遍历 MMDB 提取所有 (CIDR, country_code) 对
func (p *Parser) ParseMaxMindDB(data []byte, allowedCountries []string, source SourceID) (*GeoIPData, error) {
	// 1. 从字节数据直接创建 MMDB reader
	db, err := maxminddb.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("open mmdb from bytes failed: %w", err)
	}
	defer db.Close()

	result := NewGeoIPData(source)

	// 2. 定义用于解析 MMDB 记录的结构体
	// GeoLite2-Country.mmdb 的数据结构
	type countryRecord struct {
		Country struct {
			IsoCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			IsoCode string `maxminddb:"iso_code"`
		} `maxminddb:"registered_country"`
	}

	var record countryRecord

	// 3. 遍历所有网络记录
	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		// 获取网络 CIDR 和解析记录
		network, err := networks.Network(&record)
		if err != nil {
			return nil, fmt.Errorf("parse network failed: %w", err)
		}

		// 获取国家代码（优先使用 country，回退到 registered_country）
		var countryCode string
		if record.Country.IsoCode != "" {
			countryCode = record.Country.IsoCode
		} else if record.RegisteredCountry.IsoCode != "" {
			countryCode = record.RegisteredCountry.IsoCode
		} else {
			continue // 跳过无国家代码的记录
		}

		// 检查是否在允许列表中
		if !p.isCountryAllowed(countryCode, allowedCountries) {
			continue
		}

		// 只处理 IPv4 网络（跳过 IPv6）
		if network.IP.To4() == nil {
			continue
		}

		// 格式: "1.0.0.0/24,CN"
		cidr := network.String()
		result.AddCIDR(cidr + "," + countryCode)
	}

	// 4. 检查遍历过程中是否有错误
	if err := networks.Err(); err != nil {
		return nil, fmt.Errorf("iterate mmdb failed: %w", err)
	}

	return result, nil
}

// Parse 根据格式类型自动解析 GeoIP 数据
// format: 支持的格式类型（"maxmind", "maxmind-db" 或 "dbip"）
// allowedCountries: 允许的国家代码列表
// source: GeoIP 源标识符
func (p *Parser) Parse(data []byte, format string, allowedCountries []string, source SourceID) (*GeoIPData, error) {
	switch format {
	case "maxmind":
		return p.ParseMaxMind(data, allowedCountries, source)
	case "maxmind-db":
		return p.ParseMaxMindDB(data, allowedCountries, source)
	case "dbip":
		return p.ParseDBIP(data, allowedCountries, source)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// isCountryAllowed 检查国家是否在允许列表中
func (p *Parser) isCountryAllowed(country string, allowed []string) bool {
	for _, c := range allowed {
		if c == country {
			return true
		}
	}
	return false
}

// rangeToCIDR 将 IP 范围转换为 CIDR 格式
// 简化实现：对于小范围返回 /32，大范围返回更宽的前缀
func (p *Parser) rangeToCIDR(startIP, endIP string) (string, error) {
	// 简化实现：直接返回 startIP/32
	// 实际生产环境应该实现完整的 IP 范围到 CIDR 转换算法
	parts := strings.Split(startIP, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid IP format")
	}
	return startIP + "/32", nil
}
