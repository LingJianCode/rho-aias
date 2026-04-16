package main

import (
	"context"
	"flag"
	"fmt"

	"rho-aias/internal/bootstrap"
	"rho-aias/internal/config"
	"rho-aias/internal/frontend"
	"rho-aias/internal/handles"
	"rho-aias/internal/kernel"
	"rho-aias/internal/logger"
	"rho-aias/internal/routers"

	"github.com/gin-gonic/gin"

	"gorm.io/gorm"
)

func main() {
	configPath := flag.String("config", "config/config.yml", "Path to configuration file")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())

	result, err := kernel.CheckAndValidate()
	if err != nil {
		panic(fmt.Sprintf("[Kernel] %v", err))
	}

	cfg, err := config.NewConfig(*configPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}

	if err := logger.Init(&logger.Config{
		Level:         cfg.Log.Level,
		Format:        cfg.Log.Format,
		OutputDir:     cfg.Log.OutputDir,
		MaxAgeDays:    cfg.Log.MaxAgeDays,
		RotationHours: cfg.Log.RotationHours,
	}); err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
	defer logger.Close()

	logger.Infof("[Kernel] Detected kernel version: %s", result.CurrentVersion)
	if !result.MeetsRecommended {
		logger.Warnf("[Kernel] kernel version %s is below recommended version %s",
			result.CurrentVersion, result.RecommendedVersion)
	}
	logger.Debugf("Loaded config: %+v", cfg)

	// Phase 1: 核心基础设施 (XDP / Manual / Whitelist / BlockLog)
	core := bootstrap.InitCore(cfg)
	defer core.XDP.Close()

	if err := core.XDP.Start(); err != nil {
		logger.Fatalf("[XDP] Failed to start: %v", err)
	}
	go core.XDP.MonitorEvents()

	// 加载持久化的缓存规则到 eBPF map（必须在 Start 之后）
	core.LoadCachedRules(cfg)

	// Phase 2: 数据库初始化 + 迁移 + 动态配置恢复
	dbDeps := bootstrap.InitDatabase(cfg)
	defer dbDeps.AuthDB.Close()

	if dbDeps.AuthDB == nil {
		logger.Fatalf("[Main] Failed to initialize auth database, authentication is mandatory")
		return
	}

	var dbConn *gorm.DB
	if dbDeps.BizDB != nil {
		dbConn = dbDeps.BizDB.DB
	}

	// Phase 3: 检测模块工厂 (Intel / Geo / WAF / RateLimit / FailGuard)
	detectors := bootstrap.InitDetectors(cfg, core.XDP, ctx, dbConn, core.WhitelistHandle.GetWhitelistChecker())

	// Phase 4: 异常检测
	anomalyDeps := bootstrap.InitAnomaly(cfg, core.XDP, dbConn, core.WhitelistHandle.GetWhitelistChecker())

	// Phase 5: 认证系统 (Casbin / JWT / Captcha)
	authDeps := bootstrap.InitAuth(cfg, dbDeps.AuthDB)

	// 初始化 API Keys from config（依赖 Enforcer）
	if err := dbDeps.AuthDB.InitAPIKeysFromConfig(authDeps.Enforcer, cfg.Auth.APIKeys); err != nil {
		logger.Warnf("[Auth] Failed to initialize API keys from config: %v", err)
	}

	// Setup router
	if cfg.Log.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(logger.GinLogger(), logger.GinRecovery())
	api := r.Group("/api")

	// Phase 6: 统一路由注册
	bootstrap.RegisterAllRoutes(api, core, dbDeps, detectors, anomalyDeps, authDeps)

	// ConfigHandle (含 RestoreAll) + 注册路由
	var configHandle *handles.ConfigHandle
	if dbDeps.DynamicConfigSvc != nil {
		configHandle = bootstrap.SetupConfigHandle(
			dbDeps.DynamicConfigSvc, detectors, anomalyDeps,
			core.XDP, detectors.GeoMgr, detectors.IntelMgr,
		)
		defer configHandle.GetLifecycle().ShutdownAll()
		routers.RegisterConfigRoutes(api, configHandle, authDeps.Enforcer, authDeps.AuthService, authDeps.APIKeyService)
	}

	// Phase 6.5: 注册前端静态文件（SPA fallback）
	frontend.RegisterFrontend(r)

	// Phase 7: 启动 Server + 优雅退出
	bootstrap.StartServer(cfg, r, ctx, cancel, dbDeps.BizDB)
}
