package services

import (
	"encoding/json"
	"fmt"

	"rho-aias/internal/logger"
	"rho-aias/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DynamicConfigService 动态配置服务
// 封装 dynamic_configs 表的 CRUD 操作
type DynamicConfigService struct {
	db *gorm.DB
}

// NewDynamicConfigService 创建动态配置服务
func NewDynamicConfigService(db *gorm.DB) *DynamicConfigService {
	return &DynamicConfigService{db: db}
}

// Get 获取指定模块的动态配置
// 返回 nil 表示 DB 中无记录
func (s *DynamicConfigService) Get(module string) (*models.DynamicConfig, error) {
	var record models.DynamicConfig
	err := s.db.Where("module = ?", module).First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &record, nil
}

// Set 设置指定模块的动态配置（upsert）
func (s *DynamicConfigService) Set(module string, value interface{}) error {
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal config value: %w", err)
	}

	record := models.DynamicConfig{
		Module: module,
		Value:  string(jsonBytes),
	}

	// Upsert: 存在则更新，不存在则插入
	result := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "module"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&record)

	if result.Error != nil {
		return fmt.Errorf("failed to save dynamic config for module %s: %w", module, result.Error)
	}

	logger.Infof("[DynamicConfig] Saved config for module: %s", module)
	return nil
}

// GetAll 获取所有模块的动态配置
func (s *DynamicConfigService) GetAll() ([]models.DynamicConfig, error) {
	var records []models.DynamicConfig
	err := s.db.Find(&records).Error
	return records, err
}

// Delete 删除指定模块的动态配置
func (s *DynamicConfigService) Delete(module string) error {
	return s.db.Where("module = ?", module).Delete(&models.DynamicConfig{}).Error
}

// LoadTo 加载 DB 中的配置到目标结构体
// 如果 DB 无记录，不做任何操作（使用 YAML 默认值）
// 如果 DB 有记录，反序列化到 target
func (s *DynamicConfigService) LoadTo(module string, target interface{}) (bool, error) {
	record, err := s.Get(module)
	if err != nil {
		return false, err
	}
	if record == nil {
		return false, nil // DB 无记录，使用 YAML 值
	}

	if err := json.Unmarshal([]byte(record.Value), target); err != nil {
		return false, fmt.Errorf("failed to unmarshal config for module %s: %w", module, err)
	}

	logger.Infof("[DynamicConfig] Loaded DB config for module: %s", module)
	return true, nil
}
