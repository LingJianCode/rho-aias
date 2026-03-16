// Package blocklog 阻断日志模块
// 用于记录被 XDP 程序阻断的数据包信息
package blocklog

import (
	"sync"
	"time"
)

// BlockRecord 阻断记录
type BlockRecord struct {
	Timestamp   int64    `json:"timestamp"`    // 阻断时间戳 (Unix 纳秒)
	SrcIP       string   `json:"src_ip"`       // 源 IP 地址
	DstIP       string   `json:"dst_ip"`       // 目标 IP 地址
	MatchType   string   `json:"match_type"`   // 匹配类型 (ip4_exact, ip4_cidr, geo_block, etc.)
	RuleSource  string   `json:"rule_source"`  // 规则来源 (manual, ipsum, spamhaus, geo)
	CountryCode string   `json:"country_code"` // 国家代码 (仅 geo_block 时有值)
	PacketSize  uint32   `json:"packet_size"`  // 数据包大小
}

// BlockLog 阻断日志管理器
type BlockLog struct {
	mu      sync.RWMutex
	records []BlockRecord
	maxSize int // 最大记录数
}

// NewBlockLog 创建新的阻断日志管理器
func NewBlockLog(maxSize int) *BlockLog {
	return &BlockLog{
		records: make([]BlockRecord, 0, maxSize),
		maxSize: maxSize,
	}
}

// AddRecord 添加阻断记录
func (bl *BlockLog) AddRecord(record BlockRecord) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	// 如果超过最大记录数，删除最旧的记录
	if len(bl.records) >= bl.maxSize {
		bl.records = bl.records[1:]
	}

	bl.records = append(bl.records, record)
}

// GetRecords 获取阻断记录
// limit: 返回记录数量限制，0 表示返回所有
func (bl *BlockLog) GetRecords(limit int) []BlockRecord {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	if limit <= 0 || limit > len(bl.records) {
		limit = len(bl.records)
	}

	// 返回最近的记录（从后往前）
	result := make([]BlockRecord, limit)
	for i := 0; i < limit; i++ {
		result[i] = bl.records[len(bl.records)-1-i]
	}

	return result
}

// GetRecordsByFilter 按条件筛选阻断记录
func (bl *BlockLog) GetRecordsByFilter(filter RecordFilter) []BlockRecord {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	var result []BlockRecord

	// 从后往前遍历（最新的记录优先）
	for i := len(bl.records) - 1; i >= 0; i-- {
		record := bl.records[i]

		// 应用过滤条件
		if filter.MatchType != "" && record.MatchType != filter.MatchType {
			continue
		}
		if filter.RuleSource != "" && record.RuleSource != filter.RuleSource {
			continue
		}
		if filter.SrcIP != "" && record.SrcIP != filter.SrcIP {
			continue
		}
		if filter.CountryCode != "" && record.CountryCode != filter.CountryCode {
			continue
		}

		result = append(result, record)

		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}

	return result
}

// RecordFilter 记录过滤条件
type RecordFilter struct {
	MatchType   string `form:"match_type"`   // 匹配类型过滤
	RuleSource  string `form:"rule_source"`  // 规则来源过滤
	SrcIP       string `form:"src_ip"`       // 源 IP 过滤
	CountryCode string `form:"country_code"` // 国家代码过滤
	Limit       int    `form:"limit"`        // 返回数量限制
}

// Stats 统计信息
type Stats struct {
	TotalBlocked       int            `json:"total_blocked"`       // 总阻断数
	ByMatchType        map[string]int `json:"by_match_type"`       // 按匹配类型统计
	ByRuleSource       map[string]int `json:"by_rule_source"`      // 按规则来源统计
	ByCountry          map[string]int `json:"by_country"`          // 按国家统计
	TopBlockedIPs      []IPCount      `json:"top_blocked_ips"`     // 被阻断最多的 IP
	TopBlockedCountries []CountryCount `json:"top_blocked_countries"` // 被阻断最多的国家
}

// IPCount IP 计数
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// CountryCount 国家计数
type CountryCount struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// GetStats 获取统计信息
func (bl *BlockLog) GetStats() Stats {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	stats := Stats{
		TotalBlocked:       len(bl.records),
		ByMatchType:        make(map[string]int),
		ByRuleSource:       make(map[string]int),
		ByCountry:          make(map[string]int),
		TopBlockedIPs:      make([]IPCount, 0),
		TopBlockedCountries: make([]CountryCount, 0),
	}

	// 临时计数器
	ipCounts := make(map[string]int)
	countryCounts := make(map[string]int)

	for _, record := range bl.records {
		// 按匹配类型统计
		stats.ByMatchType[record.MatchType]++

		// 按规则来源统计
		if record.RuleSource != "" {
			stats.ByRuleSource[record.RuleSource]++
		}

		// 按国家统计
		if record.CountryCode != "" {
			stats.ByCountry[record.CountryCode]++
			countryCounts[record.CountryCode]++
		}

		// IP 计数
		ipCounts[record.SrcIP]++
	}

	// 获取 Top 10 IP
	stats.TopBlockedIPs = getTopIPs(ipCounts, 10)

	// 获取 Top 10 国家
	stats.TopBlockedCountries = getTopCountries(countryCounts, 10)

	return stats
}

// getTopIPs 获取被阻断最多的 IP
func getTopIPs(ipCounts map[string]int, limit int) []IPCount {
	// 使用简单的排序算法
	ips := make([]IPCount, 0, len(ipCounts))
	for ip, count := range ipCounts {
		ips = append(ips, IPCount{IP: ip, Count: count})
	}

	// 按计数降序排序
	for i := 0; i < len(ips); i++ {
		for j := i + 1; j < len(ips); j++ {
			if ips[j].Count > ips[i].Count {
				ips[i], ips[j] = ips[j], ips[i]
			}
		}
	}

	if len(ips) > limit {
		ips = ips[:limit]
	}

	return ips
}

// getTopCountries 获取被阻断最多的国家
func getTopCountries(countryCounts map[string]int, limit int) []CountryCount {
	countries := make([]CountryCount, 0, len(countryCounts))
	for country, count := range countryCounts {
		countries = append(countries, CountryCount{Country: country, Count: count})
	}

	// 按计数降序排序
	for i := 0; i < len(countries); i++ {
		for j := i + 1; j < len(countries); j++ {
			if countries[j].Count > countries[i].Count {
				countries[i], countries[j] = countries[j], countries[i]
			}
		}
	}

	if len(countries) > limit {
		countries = countries[:limit]
	}

	return countries
}

// Clear 清空所有记录
func (bl *BlockLog) Clear() {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	bl.records = make([]BlockRecord, 0, bl.maxSize)
}

// Count 获取记录总数
func (bl *BlockLog) Count() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	return len(bl.records)
}

// CreateRecord 创建阻断记录的便捷方法
func CreateRecord(srcIP, dstIP, matchType, ruleSource, countryCode string, packetSize uint32) BlockRecord {
	return BlockRecord{
		Timestamp:   time.Now().UnixNano(),
		SrcIP:       srcIP,
		DstIP:       dstIP,
		MatchType:   matchType,
		RuleSource:  ruleSource,
		CountryCode: countryCode,
		PacketSize:  packetSize,
	}
}
