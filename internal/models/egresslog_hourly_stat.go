package models

// EgresslogHourlyStat Egress 丢包日志小时统计快照
// 每个 (hour, dimension, dim_value) 组合对应一条记录
type EgresslogHourlyStat struct {
	Hour      string `gorm:"primaryKey;size:13" json:"hour"`      // 格式: "2026-04-17T14"
	Dimension string `gorm:"primaryKey;size:20" json:"dimension"` // 'total' | 'dst_ip'
	DimValue  string `gorm:"primaryKey;size:50" json:"dim_value"` // 维度值，total时为空串
	Count     int64  `gorm:"not null;default:0" json:"count"`
}

func (EgresslogHourlyStat) TableName() string { return "egresslog_hourly_stats" }
