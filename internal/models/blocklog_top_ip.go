package models

import "time"

// BlocklogTopIP 阻断日志 Top IP 持久化
type BlocklogTopIP struct {
	IP        string    `gorm:"primaryKey;size:45" json:"ip"`          // IP 地址
	Count     int64     `gorm:"not null;default:0" json:"count"`       // 累计阻断次数
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (BlocklogTopIP) TableName() string { return "blocklog_top_ips" }
