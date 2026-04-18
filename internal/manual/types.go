// Package manual 规则持久化模块
// 负责手动添加规则（黑名单/白名单）的本地持久化，实现重启后恢复功能
package manual

import (
	"time"
)

// 缓存文件名常量
const (
	CacheFileBlacklist = "blacklist_cache.bin"
	CacheFileWhitelist = "whitelist_cache.bin"
)

// RuleEntry 统一规则条目（黑名单/白名单通用）
type RuleEntry struct {
	Value   string    // IP/CIDR 值
	AddedAt time.Time // 添加时间 (使用 time.RFC3339 格式化输出)
	Remark  string    // 备注/说明
}

// RuleCacheData 统一规则缓存数据结构
type RuleCacheData struct {
	Version   uint32               // 版本号
	Timestamp int64                // Unix 时间戳
	Rules     map[string]RuleEntry // key: value (IP/CIDR), value: 规则条目
}

// NewRuleCacheData 创建新的缓存数据
func NewRuleCacheData() *RuleCacheData {
	return &RuleCacheData{
		Version:   1,
		Timestamp: time.Now().Unix(),
		Rules:     make(map[string]RuleEntry),
	}
}

// NewRuleEntry 创建新的规则条目
func NewRuleEntry(value string) *RuleEntry {
	return &RuleEntry{
		Value:   value,
		AddedAt: time.Now(),
	}
}

// NewRuleEntryWithRemark 创建带备注的规则条目
func NewRuleEntryWithRemark(value, remark string) *RuleEntry {
	return &RuleEntry{
		Value:   value,
		AddedAt: time.Now(),
		Remark:  remark,
	}
}

// AddRule 添加规则到缓存数据
func (d *RuleCacheData) AddRule(entry RuleEntry) {
	d.Rules[entry.Value] = entry
	d.Timestamp = time.Now().Unix()
}

// RemoveRule 从缓存数据中移除规则
func (d *RuleCacheData) RemoveRule(value string) {
	delete(d.Rules, value)
	d.Timestamp = time.Now().Unix()
}

// HasRule 检查规则是否存在
func (d *RuleCacheData) HasRule(value string) bool {
	_, exists := d.Rules[value]
	return exists
}

// RuleCount 返回规则总数
func (d *RuleCacheData) RuleCount() int {
	return len(d.Rules)
}

// GetValues 获取所有规则的值列表
func (d *RuleCacheData) GetValues() []string {
	values := make([]string, 0, len(d.Rules))
	for _, entry := range d.Rules {
		values = append(values, entry.Value)
	}
	return values
}
