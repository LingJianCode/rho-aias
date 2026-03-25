// Package manual 手动规则持久化模块
// 负责手动添加规则的本地持久化，实现重启后恢复功能
package manual

import (
	"errors"
	"time"
)

// SourceID 手动规则源标识符
const SourceManual = "manual"

// ManualRuleEntry 单个手动规则条目
type ManualRuleEntry struct {
	Value   string    // IP/CIDR/MAC 值
	AddedAt time.Time // 添加时间
	Source  string    // 来源 (始终为 "manual")
}

// CacheData 持久化缓存数据结构（使用 gob 二进制格式）
type CacheData struct {
	Version   uint32                       // 版本号
	Timestamp int64                        // Unix 时间戳
	Rules     map[string]ManualRuleEntry  // key: value (IP/CIDR/MAC), value: 规则条目
}

// NewCacheData 创建新的缓存数据
func NewCacheData() *CacheData {
	return &CacheData{
		Version:   1,
		Timestamp: time.Now().Unix(),
		Rules:     make(map[string]ManualRuleEntry),
	}
}

// NewManualRuleEntry 创建新的手动规则条目
func NewManualRuleEntry(value string) *ManualRuleEntry {
	return &ManualRuleEntry{
		Value:   value,
		AddedAt: time.Now(),
		Source:  SourceManual,
	}
}

// AddRule 添加规则到缓存数据
func (d *CacheData) AddRule(entry ManualRuleEntry) {
	d.Rules[entry.Value] = entry
	d.Timestamp = time.Now().Unix()
}

// RemoveRule 从缓存数据中移除规则
func (d *CacheData) RemoveRule(value string) {
	delete(d.Rules, value)
	d.Timestamp = time.Now().Unix()
}

// HasRule 检查规则是否存在
func (d *CacheData) HasRule(value string) bool {
	_, exists := d.Rules[value]
	return exists
}

// RuleCount 返回规则总数
func (d *CacheData) RuleCount() int {
	return len(d.Rules)
}

// GetValues 获取所有规则的值列表
func (d *CacheData) GetValues() []string {
	values := make([]string, 0, len(d.Rules))
	for _, entry := range d.Rules {
		values = append(values, entry.Value)
	}
	return values
}

var ErrManualCacheNotFound = errors.New("manual cache not found")

// SourceWhitelist 白名单源标识符
const SourceWhitelist = "whitelist"

// WhitelistRuleEntry 白名单规则条目
type WhitelistRuleEntry struct {
	Value   string    // IP/CIDR 值
	AddedAt time.Time // 添加时间
	Source  string    // 来源 (始终为 "whitelist")
}

// WhitelistCacheData 白名单持久化缓存数据结构
type WhitelistCacheData struct {
	Version   uint32                          // 版本号
	Timestamp int64                           // Unix 时间戳
	Rules     map[string]WhitelistRuleEntry   // key: value (IP/CIDR), value: 规则条目
}

// NewWhitelistCacheData 创建新的白名单缓存数据
func NewWhitelistCacheData() *WhitelistCacheData {
	return &WhitelistCacheData{
		Version:   1,
		Timestamp: time.Now().Unix(),
		Rules:     make(map[string]WhitelistRuleEntry),
	}
}

// NewWhitelistRuleEntry 创建新的白名单规则条目
func NewWhitelistRuleEntry(value string) *WhitelistRuleEntry {
	return &WhitelistRuleEntry{
		Value:   value,
		AddedAt: time.Now(),
		Source:  SourceWhitelist,
	}
}

// AddWhitelistRule 添加白名单规则到缓存数据
func (d *WhitelistCacheData) AddWhitelistRule(entry WhitelistRuleEntry) {
	d.Rules[entry.Value] = entry
	d.Timestamp = time.Now().Unix()
}

// RemoveWhitelistRule 从缓存数据中移除白名单规则
func (d *WhitelistCacheData) RemoveWhitelistRule(value string) {
	delete(d.Rules, value)
	d.Timestamp = time.Now().Unix()
}

// HasWhitelistRule 检查白名单规则是否存在
func (d *WhitelistCacheData) HasWhitelistRule(value string) bool {
	_, exists := d.Rules[value]
	return exists
}

// WhitelistRuleCount 返回白名单规则总数
func (d *WhitelistCacheData) WhitelistRuleCount() int {
	return len(d.Rules)
}

// GetWhitelistValues 获取所有白名单规则的值列表
func (d *WhitelistCacheData) GetWhitelistValues() []string {
	values := make([]string, 0, len(d.Rules))
	for _, entry := range d.Rules {
		values = append(values, entry.Value)
	}
	return values
}

var ErrWhitelistCacheNotFound = errors.New("whitelist cache not found")
