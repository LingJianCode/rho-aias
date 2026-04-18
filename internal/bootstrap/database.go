package bootstrap

import (
	"rho-aias/internal/config"
	"rho-aias/internal/database"
	"rho-aias/internal/logger"
	"rho-aias/internal/services"
)

// Databases 数据库初始化结果
type Databases struct {
	AuthDB           *database.Database
	BizDB            *database.Database
	DynamicConfigSvc *services.DynamicConfigService
}

// InitDatabase 初始化数据库、迁移表、恢复动态配置
func InitDatabase(cfg *config.Config) *Databases {
	authDB, err := database.NewDatabase(cfg.Auth.DatabasePath, cfg.Log.Level == "debug")
	if err != nil {
		logger.Fatalf("[Main] Failed to initialize auth database (authentication is mandatory): %v", err)
	}

	var bizDB *database.Database
	bizDB, err = database.NewDatabase(cfg.Business.DatabasePath, cfg.Log.Level == "debug")
	if err != nil {
		logger.Fatalf("[Main] Failed to initialize business database: %v ", err)
	}

	if err := authDB.AutoMigrateAuth(); err != nil {
		logger.Fatalf("[Main] Failed to migrate auth database: %v", err)
	}

	var dynamicConfigSvc *services.DynamicConfigService
	if err := bizDB.AutoMigrateBusiness(); err != nil {
		logger.Fatalf("[Main] Failed to migrate business database: %v", err)
	}

	banRecordService := services.NewBanRecordService(bizDB.DB)
	if count, err := banRecordService.MarkAllActiveAsAutoUnblock(); err != nil {
		logger.Warnf("[Main] Failed to mark active bans as auto_unblock: %v", err)
	} else if count > 0 {
		logger.Infof("[Main] Marked %d active ban records as auto_unblock (eBPF state lost on restart)", count)
	}

	dynamicConfigSvc = services.NewDynamicConfigService(bizDB.DB)
	loadDynamicConfigFromDB(dynamicConfigSvc, cfg)

	return &Databases{
		AuthDB:           authDB,
		BizDB:            bizDB,
		DynamicConfigSvc: dynamicConfigSvc,
	}
}
