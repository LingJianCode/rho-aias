package database

import (
	"fmt"
	"log"

	"rho-aias/internal/auth/password"
	"rho-aias/internal/casbin"
	"rho-aias/internal/models"

	"github.com/glebarez/go-sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database 数据库封装
type Database struct {
	*gorm.DB
}

// NewDatabase 创建数据库连接
func NewDatabase(dsn string) (*Database, error) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}

	// 配置 SQLite WAL 模式
	if err := db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		log.Printf("Warning: failed to enable WAL mode: %v", err)
	}

	// 配置同步模式
	if err := db.Exec("PRAGMA synchronous=NORMAL").Error; err != nil {
		log.Printf("Warning: failed to set synchronous mode: %v", err)
	}

	return &Database{db}, nil
}

// AutoMigrate 自动迁移
func (db *Database) AutoMigrate() error {
	return db.DB.AutoMigrate(
		&models.User{},
		&models.APIKey{},
		&models.AuditLog{},
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
		log.Printf("Warning: failed to assign admin role: %v", err)
	}

	log.Println("[Database] Default admin user created: admin / admin123")
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
