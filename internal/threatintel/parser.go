// Package threatintel 威胁情报模块
package threatintel

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// Parser 威胁情报数据解析器
// 支持多种威胁情报源格式（IPSum、Spamhaus 等）
type Parser struct{}

// NewParser 创建新的威胁情报数据解析器
func NewParser() *Parser {
	return &Parser{}
}

// ParseIpsum 解析 IPSum 格式的威胁情报数据
// IPSum 格式说明:
//   - 以 # 开头的行为注释
//   - 数据格式: IP地址 + 空格 + 黑名单数量
//   - 示例: "5.187.35.21     11"
//   - 支持 CIDR 格式: "1.2.3.0/24"
func (p *Parser) ParseIpsum(data []byte, source SourceID) (*IntelData, error) {
	result := NewIntelData(source)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释行（以 # 开头）
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析行: "IP地址  数字"
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		// 第一部分是 IP 地址或 CIDR
		ip := parts[0]

		// 判断是精确 IP 还是 CIDR
		if strings.Contains(ip, "/") {
			result.AddCIDR(ip)
		} else {
			result.AddIPv4(ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	return result, nil
}

// ParseSpamhaus 解析 Spamhaus DROP 格式的威胁情报数据
// Spamhaus DROP 格式说明:
//   - 以 ; 开头的行为注释
//   - 数据格式: IP地址/CIDR ; 注释
//   - 示例: "1.10.16.0/20 ; SBL256894"
//   - 示例: "2.57.122.0/24 ; SBL636050"
func (p *Parser) ParseSpamhaus(data []byte, source SourceID) (*IntelData, error) {
	result := NewIntelData(source)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释行（以 ; 开头）
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// 解析行: "IP地址;注释"
		parts := strings.Split(line, ";")
		if len(parts) == 0 {
			continue
		}

		// 取第一部分作为 IP/CIDR
		ip := strings.TrimSpace(parts[0])
		if ip == "" {
			continue
		}

		// 判断是精确 IP 还是 CIDR
		if strings.Contains(ip, "/") {
			result.AddCIDR(ip)
		} else {
			result.AddIPv4(ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	return result, nil
}

// Parse 根据格式类型自动解析威胁情报数据
// format: 支持的格式类型（"ipsum" 或 "spamhaus"）
// source: 威胁情报源标识符
func (p *Parser) Parse(data []byte, format string, source SourceID) (*IntelData, error) {
	switch format {
	case "ipsum":
		return p.ParseIpsum(data, source)
	case "spamhaus":
		return p.ParseSpamhaus(data, source)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}
