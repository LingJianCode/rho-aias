// Package feed 为威胁情报、地域封禁等数据馈送（Data Feed）模块提供公共基础设施，
// 包括泛型持久化缓存（Cache）、HTTP 数据获取器（Fetcher）、
// 并发互斥锁池（MutexPool）、数据源状态（SourceStatus）和数据库状态记录辅助函数。
//
// 各模块通过泛型参数 [T] 传入自己的数据类型，实现类型安全的复用。
package feed

import "time"

// SourceStatus 单个数据源的运行状态
// 被 ThreatIntel 和 GeoBlocking 等模块共用
type SourceStatus struct {
	Enabled    bool      `json:"enabled"`     // 是否启用该数据源
	LastUpdate time.Time `json:"last_update"` // 最后更新时间
	Success    bool      `json:"success"`     // 最后一次更新是否成功
	RuleCount  int       `json:"rule_count"`  // 该数据源的规则数量
	Error      string    `json:"error"`       // 错误信息（如果更新失败）
}

// SetSuccess 更新为成功状态（用于避免死锁的内联状态更新场景）
func (s *SourceStatus) SetSuccess(now time.Time, ruleCount int) {
	s.Enabled = true
	s.LastUpdate = now
	s.Success = true
	s.RuleCount = ruleCount
	s.Error = ""
}

// SetFailure 更新为失败状态（用于避免死锁的内联状态更新场景）
func (s *SourceStatus) SetFailure(now time.Time, errMsg string) {
	s.Enabled = true
	s.LastUpdate = now
	s.Success = false
	s.RuleCount = 0
	s.Error = errMsg
}
