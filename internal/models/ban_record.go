package models

import "time"

// BanRecord 封禁记录模型 - 记录各来源的 IP 封禁操作，用于审计
type BanRecord struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	IP          string     `gorm:"size:45;not null;index:idx_ip_source_active" json:"ip"`       // 封禁 IP
	Source      string     `gorm:"size:20;not null;index:idx_ip_source_active" json:"source"`    // 封禁来源: waf, rate_limit, anomaly
	Reason      string     `gorm:"size:255" json:"reason"`                        // 封禁原因
	Duration    int        `gorm:"not null" json:"duration"`                      // 封禁时长（秒）
	Status      string     `gorm:"size:20;not null;default:active" json:"status"` // 状态: active, expired, manual_unblock, auto_unblock
	CreatedAt   time.Time  `gorm:"index" json:"created_at"`                       // 封禁时间
	ExpiresAt   time.Time  `json:"expires_at"`                                   // 过期时间
	UnblockedAt *time.Time `json:"unblocked_at"`                                 // 解封时间（手动解封时记录）
}

// TableName 指定表名
func (BanRecord) TableName() string {
	return "ban_records"
}

// 封禁来源常量
const (
	BanSourceWAF        = "waf"
	BanSourceRateLimit  = "rate_limit"
	BanSourceAnomaly    = "anomaly"
	BanSourceManual     = "manual"
	BanSourceFailGuard  = "failguard"
)

// 封禁状态常量
const (
	BanStatusActive        = "active"
	BanStatusExpired       = "expired"
	BanStatusManualUnblock = "manual_unblock"
	BanStatusAutoUnblock   = "auto_unblock" // 启动时自动解封（eBPF map 状态丢失）
)
