package source

import (
	"fmt"
	"time"

	"rho-aias/internal/models"

	"gorm.io/gorm"
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
