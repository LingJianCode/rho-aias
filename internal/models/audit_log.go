package models

import (
	"time"
)

// AuditLog 审计日志模型
type AuditLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"index" json:"user_id"`              // 操作用户 ID
	Username  string    `gorm:"size:50" json:"username"`           // 操作用户名
	Action    string    `gorm:"size:50;not null" json:"action"`    // 操作类型
	Resource  string    `gorm:"size:100;not null" json:"resource"` // 资源类型
	ResourceID string   `gorm:"size:100" json:"resource_id"`       // 资源 ID
	Detail    string    `gorm:"type:text" json:"detail"`           // 操作详情（JSON）
	IP        string    `gorm:"size:45" json:"ip"`                 // 客户端 IP
	UserAgent string    `gorm:"size:255" json:"user_agent"`        // User Agent
	Status    string    `gorm:"size:20;default:success" json:"status"` // success/failed
	Error     string    `gorm:"type:text" json:"error"`            // 错误信息（如果有）
	CreatedAt time.Time `json:"created_at"`
}

// TableName 指定表名
func (AuditLog) TableName() string {
	return "audit_logs"
}

// 预定义的操作类型
const (
	ActionLogin         = "login"
	ActionLogout        = "logout"
	ActionChangePassword = "change_password"

	ActionCreateUser = "create_user"
	ActionUpdateUser = "update_user"
	ActionDeleteUser = "delete_user"

	ActionCreateAPIKey = "create_api_key"
	ActionRevokeAPIKey = "revoke_api_key"

	ActionAddRule    = "add_rule"
	ActionDeleteRule = "delete_rule"
	ActionClearLogs  = "clear_logs"

	ActionUpdateIntel = "update_intel"
	ActionUpdateGeo   = "update_geo"
)

// 预定义的资源类型
const (
	ResourceUser   = "user"
	ResourceAPIKey = "api_key"
	ResourceRule   = "firewall_rule"
	ResourceLog    = "block_log"
	ResourceIntel  = "threat_intel"
	ResourceGeo    = "geo_blocking"
)
