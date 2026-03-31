// Package threatintel 威胁情报模块
// 集成外部威胁情报源（IPSum、Spamhaus 等），实现自动同步、本地持久化和高性能批量更新
package threatintel

import (
	"errors"
	"time"
)

// SourceID 威胁情报源标识符
type SourceID string

const (
	SourceIpsum    SourceID = "ipsum"    // IPSum 威胁情报源
	SourceSpamhaus SourceID = "spamhaus" // Spamhaus 威胁情报源
	SourceManual   SourceID = "manual"   // 手动添加（未来）
	SourceWAF      SourceID = "waf"      // WAF（未来）
	SourceDDoS     SourceID = "ddos"     // DDoS 检测（未来）
)

// IntelData 威胁情报数据（仅支持 IPv4）
type IntelData struct {
	IPv4Exact []string  // 精确匹配的 IPv4 地址列表
	IPv4CIDR  []string  // IPv4 CIDR 地址块列表
	Timestamp time.Time // 数据时间戳
	Source    SourceID  // 数据来源标识
}

// CacheData 持久化缓存数据结构（使用 gob 二进制格式）
type CacheData struct {
	Version   uint32                 // 版本号
	Timestamp int64                  // Unix 时间戳
	Sources   map[SourceID]IntelData // 各情报源的数据
}

// Status 威胁情报模块状态
type Status struct {
	Enabled    bool                      `json:"enabled"`     // 是否启用威胁情报功能
	LastUpdate time.Time                 `json:"last_update"` // 最后更新时间
	TotalRules int                       `json:"total_rules"` // 总规则数量
	Sources    map[SourceID]SourceStatus `json:"sources"`     // 各情报源的状态
}

// SourceStatus 单个威胁情报源的状态
type SourceStatus struct {
	Enabled    bool      `json:"enabled"`     // 是否启用该情报源
	LastUpdate time.Time `json:"last_update"` // 最后更新时间
	Success    bool      `json:"success"`     // 最后一次更新是否成功
	RuleCount  int       `json:"rule_count"`  // 该情报源的规则数量
	Error      string    `json:"error"`       // 错误信息（如果更新失败）
}

// NewIntelData 创建新的威胁情报数据
func NewIntelData(source SourceID) *IntelData {
	return &IntelData{
		IPv4Exact: make([]string, 0),
		IPv4CIDR:  make([]string, 0),
		Timestamp: time.Now(),
		Source:    source,
	}
}

// NewCacheData 创建新的缓存数据
func NewCacheData() *CacheData {
	return &CacheData{
		Version:   1,
		Timestamp: time.Now().Unix(),
		Sources:   make(map[SourceID]IntelData),
	}
}

// AddIPv4 添加 IPv4 地址（精确匹配）
func (d *IntelData) AddIPv4(ip string) {
	d.IPv4Exact = append(d.IPv4Exact, ip)
}

// AddCIDR 添加 IPv4 CIDR 地址块
func (d *IntelData) AddCIDR(cidr string) {
	d.IPv4CIDR = append(d.IPv4CIDR, cidr)
}

// TotalCount 返回总规则数量
func (d *IntelData) TotalCount() int {
	return len(d.IPv4Exact) + len(d.IPv4CIDR)
}

var ErrThreatIntelCacheNotFound = errors.New("threat intelligence cache not found")
