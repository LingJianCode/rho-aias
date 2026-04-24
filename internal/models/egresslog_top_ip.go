package models

import "time"

// EgresslogTopIP Egress 丢包日志 Top IP 持久化
// 复合主键 (hour, ip)：支持按时间范围查询 Top IP
type EgresslogTopIP struct {
	Hour      string    `gorm:"primaryKey;size:13" json:"hour"`  // 格式: "2026-04-17T15"
	IP        string    `gorm:"primaryKey;size:45" json:"ip"`    // 目标 IP 地址
	Count     int64     `gorm:"not null;default:0" json:"count"` // 该小时丢包次数
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (EgresslogTopIP) TableName() string { return "egresslog_top_ips" }
