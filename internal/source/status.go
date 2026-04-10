package source

import "time"

// SourceStatus 单个数据源的运行状态
// 被 ThreatIntel 和 GeoBlocking 等模块共用
type SourceStatus struct {
	Enabled    bool      // 是否启用该数据源
	LastUpdate time.Time // 最后更新时间
	Success    bool      // 最后一次更新是否成功
	RuleCount  int       // 该数据源的规则数量
	Error      string    // 错误信息（如果更新失败）
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
