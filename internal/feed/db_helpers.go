// Package feed 为威胁情报、地域封禁等数据馈送（Data Feed）模块提供公共基础设施，
// 包括 HTTP 数据获取器（Fetcher）、并发互斥锁池（MutexPool）、
// 数据源状态（SourceStatus）和数据库状态记录辅助函数。
package feed

import (
	"fmt"
	"time"

	"rho-aias/internal/models"

	"gorm.io/gorm"
)

// SourceType 数据源类型常量
const (
	SourceTypeIntel      = "intel"       // 威胁情报源类型
	SourceTypeGeoBlocking = "geo_blocking" // 地域封禁源类型
)

// RecordStatus 记录数据源更新状态到数据库
func RecordStatus(db *gorm.DB, sourceType, sourceID, sourceName, status string, ruleCount int, errMsg string, duration int64) error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}

	record := &models.SourceStatusRecord{
		SourceType:   sourceType,
		SourceID:     sourceID,
		SourceName:   sourceName,
		Status:       status,
		RuleCount:    ruleCount,
		ErrorMessage: errMsg,
		Duration:     int(duration),
		UpdatedAt:    time.Now(),
		CreatedAt:    time.Now(),
	}

	if err := db.Create(record).Error; err != nil {
		return fmt.Errorf("failed to create status record: %w", err)
	}

	return nil
}

// CleanOldRecords 清理指定数据源的过期记录（超过 30 天）
func CleanOldRecords(db *gorm.DB, sourceType, sourceID string) error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}

	return models.CleanOldRecords(db, sourceType, sourceID)
}

// GetLatestSourceStatus 查询指定数据源最新的状态记录（用于 GetStatus 接口）
// 返回 nil 表示无历史记录
func GetLatestSourceStatus(db *gorm.DB, sourceType, sourceID string) (*models.SourceStatusRecord, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	var record models.SourceStatusRecord
	err := db.Where("source_type = ? AND source_id = ?", sourceType, sourceID).
		Order("id DESC").
		First(&record).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query source status: %w", err)
	}
	return &record, nil
}
