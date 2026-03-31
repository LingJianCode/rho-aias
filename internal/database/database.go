package database

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"rho-aias/internal/auth/password"
	"rho-aias/internal/casbin"
	"rho-aias/internal/config"
	"rho-aias/internal/logger"
	"rho-aias/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Database 数据库封装
type Database struct {
	*gorm.DB
}

// NewDatabase 创建数据库连接
func NewDatabase(dsn string) (*Database, error) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}

	// 配置 SQLite WAL 模式
	if err := db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		logger.Warnf("[Database] Failed to enable WAL mode: %v", err)
	}

	// 配置同步模式
	if err := db.Exec("PRAGMA synchronous=NORMAL").Error; err != nil {
		logger.Warnf("[Database] Failed to set synchronous mode: %v", err)
	}

	return &Database{db}, nil
}

// AutoMigrateAuth 迁移认证相关表
func (db *Database) AutoMigrateAuth() error {
	return db.DB.AutoMigrate(
		&models.User{},
		&models.APIKey{},
		&models.AuditLog{},
	)
}

// AutoMigrateBusiness 迁移业务数据表
func (db *Database) AutoMigrateBusiness() error {
	return db.DB.AutoMigrate(
		&models.SourceStatusRecord{},
		&models.BanRecord{},
	)
}

// InitDefaultUser 初始化默认管理员用户
func (db *Database) InitDefaultUser(enforcer *casbin.Enforcer) error {
	// 检查是否存在管理员
	var count int64
	db.Model(&models.User{}).Where("role = ?", "admin").Count(&count)
	if count > 0 {
		return nil // 已存在管理员，无需初始化
	}

	// 创建默认管理员
	admin := &models.User{
		Username: "admin",
		Password: password.MustHashPassword("admin123"),
		Nickname: "Administrator",
		Role:     "admin",
		Active:   true,
	}

	if err := db.Create(admin).Error; err != nil {
		return fmt.Errorf("failed to create default admin: %w", err)
	}

	// 为管理员分配角色
	if err := enforcer.AssignRoleToUser(admin.ID, "admin"); err != nil {
		logger.Warnf("[Database] Failed to assign admin role: %v", err)
	}

	logger.Info("[Database] Default admin user created: admin / admin123")
	return nil
}

// InitAPIKeysFromConfig 从配置文件初始化 API Keys
func (db *Database) InitAPIKeysFromConfig(enforcer *casbin.Enforcer, apiKeys []config.APIKeyConfig) error {
	if len(apiKeys) == 0 {
		return nil
	}

	// 获取管理员用户 ID
	var admin models.User
	db.Where("role = ?", "admin").First(&admin)
	if admin.ID == 0 {
		return fmt.Errorf("admin user not found, cannot create API keys")
	}

	createdCount := 0
	for _, keyConfig := range apiKeys {
		// 跳过空的 Key
		if keyConfig.Key == "" {
			logger.Warnf("[Database] Skipping API key with empty value: %s", keyConfig.Name)
			continue
		}

		// 检查是否已存在相同 Key（计算 Hash 后比较）
		hash := sha256.Sum256([]byte(keyConfig.Key))
		hashStr := hex.EncodeToString(hash[:])
		var count int64
		db.Model(&models.APIKey{}).Where("key = ?", hashStr).Count(&count)
		if count > 0 {
			logger.Infof("[Database] API key already exists: %s", keyConfig.Name)
			continue
		}

		// 计算 Key 前缀（用于显示）
		keyPrefix := "sk_live_"
		if len(keyConfig.Key) > 16 {
			keyPrefix += keyConfig.Key[8:16]
		} else {
			keyPrefix += keyConfig.Key
		}

		// 转换权限列表为 JSON
		permissionsJSON := "[\"*\"]"
		if len(keyConfig.Permissions) > 0 {
			permBytes, err := json.Marshal(keyConfig.Permissions)
			if err != nil {
				logger.Warnf("[Database] Failed to marshal permissions for %s: %v", keyConfig.Name, err)
				continue
			}
			permissionsJSON = string(permBytes)
		}

		// 创建 API Key（存储 Hash 值）
		apiKey := &models.APIKey{
			Name:        keyConfig.Name,
			Key:         hashStr,
			KeyPrefix:   keyPrefix,
			UserID:      admin.ID,
			Permissions: permissionsJSON,
			Active:      true,
		}

		if err := db.Create(apiKey).Error; err != nil {
			logger.Errorf("[Database] Failed to create API key %s: %v", keyConfig.Name, err)
			continue
		}

		// 设置 API Key 权限
		var permissions []string
		if len(keyConfig.Permissions) == 1 && keyConfig.Permissions[0] == "*" {
			// 全部权限：添加通配符策略
			permissions = []string{"*:*"}
		} else {
			// 使用配置中的权限列表
			permissions = keyConfig.Permissions
		}

		if err := enforcer.AddAPIKeyPermissions(apiKey.Key, permissions); err != nil {
			logger.Warnf("[Database] Failed to add permissions for API key %s: %v", keyConfig.Name, err)
		}

		createdCount++
		logger.Infof("[Database] API key created: %s (prefix: %s)", keyConfig.Name, keyPrefix)
	}

	if createdCount > 0 {
		logger.Infof("[Database] Total API keys created from config: %d", createdCount)
	}

	return nil
}

// Close 关闭数据库连接
func (db *Database) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
