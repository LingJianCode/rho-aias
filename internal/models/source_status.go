package models

import (
	"time"

	"gorm.io/gorm"
)

// SourceStatusRecord 数据源状态记录模型
// 记录威胁情报和地域封禁数据源的更新状态
type SourceStatusRecord struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	SourceType   string    `gorm:"size:20;not null;index" json:"source_type"`   // intel / geo_blocking
	SourceID     string    `gorm:"size:50;not null;index" json:"source_id"`     // ipsum / spamhaus / maxmind
	SourceName   string    `gorm:"size:100" json:"source_name"`                  // 展示名称
	Status       string    `gorm:"size:20;not null" json:"status"`               // success / failed
	RuleCount    int       `gorm:"default:0" json:"rule_count"`                  // 规则数量
	ErrorMessage string    `gorm:"type:text" json:"error_message"`              // 错误信息（失败时）
	Duration     int       `gorm:"default:0" json:"duration"`                    // 更新耗时（毫秒）
	UpdatedAt    time.Time `gorm:"not null" json:"updated_at"`                  // 记录更新时间
	CreatedAt    time.Time `json:"created_at"`                                  // 任务触发时间
}

// TableName 指定表名
func (SourceStatusRecord) TableName() string {
	return "source_status_records"
}

// CleanOldRecords 清理指定数据源的过期记录（超过 30 天）
func CleanOldRecords(db *gorm.DB, sourceType, sourceID string) error {
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	return db.Where("source_type = ? AND source_id = ? AND updated_at < ?", sourceType, sourceID, thirtyDaysAgo).Delete(&SourceStatusRecord{}).Error
}
