package models

import "time"

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
