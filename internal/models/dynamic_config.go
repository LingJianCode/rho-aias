package models

import "time"

// 支持动态配置的合法模块名常量
const (
	ModuleFailGuard        = "failguard"
	ModuleWAF              = "waf"
	ModuleRateLimit        = "rate_limit"
	ModuleAnomalyDetection = "anomaly_detection"
	ModuleGeoBlocking      = "geo_blocking"
	ModuleIntel            = "intel"
	ModuleBlocklogEvents   = "blocklog_events"
	ModuleEgressLimit      = "egress_limit"
)

// IsValidModule 检查模块名是否合法（供 handles、services 等外部包调用）
func IsValidModule(module string) bool {
	switch module {
	case ModuleFailGuard, ModuleWAF, ModuleRateLimit, ModuleAnomalyDetection, ModuleGeoBlocking, ModuleIntel, ModuleBlocklogEvents, ModuleEgressLimit:
		return true
	default:
		return false
	}
}

// DynamicConfig 动态配置模型
// 存储各模块可热更新的配置，JSON 格式，复用 business.db
type DynamicConfig struct {
	Module    string    `gorm:"primaryKey;size:50" json:"module"` // 模块名: failguard, waf, rate_limit, anomaly_detection, geo_blocking, intel
	Value     string    `gorm:"type:text;not null" json:"value"`  // JSON 格式的模块配置
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"` // 最后更新时间
}

// TableName 指定表名
func (DynamicConfig) TableName() string {
	return "dynamic_configs"
}
