package models

import "time"

// HourlyStat 小时阻断统计
type HourlyStat struct {
	Hour       string    `gorm:"primaryKey;size:13" json:"hour"`        // 格式: "2026-04-10T14"
	RuleSource string    `gorm:"primaryKey;size:50" json:"rule_source"` // 规则来源
	Count      int64     `gorm:"not null;default:0" json:"count"`      // 计数
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (HourlyStat) TableName() string {
	return "hourly_stats"
}
