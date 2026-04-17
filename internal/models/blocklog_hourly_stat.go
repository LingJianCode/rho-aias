package models

import "time"

// BlocklogHourlyStat 阻断日志小时统计快照（替代原 HourlyStat）
// 每个 (hour, dimension, dim_value) 组合对应一条记录
type BlocklogHourlyStat struct {
	Hour      string    `gorm:"primaryKey;size:13" json:"hour"`       // 格式: "2026-04-17T14"
	Dimension string    `gorm:"primaryKey;size:20" json:"dimension"`  // 'rule_source' | 'country' | 'total'
	DimValue  string    `gorm:"primaryKey;size:50" json:"dim_value"`  // 维度值，total时为空串
	Count     int64     `gorm:"not null;default:0" json:"count"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (BlocklogHourlyStat) TableName() string { return "blocklog_hourly_stats" }
