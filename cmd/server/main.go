package main

import (
	"context"
	"flag"
	"fmt"

	"rho-aias/internal/bootstrap"
	"rho-aias/internal/config"
	"rho-aias/internal/frontend"
	"rho-aias/internal/kernel"
	"rho-aias/internal/logger"

	"github.com/gin-gonic/gin"
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

	// 数据库初始化 + 迁移 + 动态配置恢复
	dbs := bootstrap.InitDatabase(cfg)
	defer dbs.AuthDB.Close()

	// AuthDB / BizDB 在 InitDatabase 中已保证非 nil（失败时 FatalExit）
	dbConn := dbs.BizDB.DB

	// 核心基础设施 (XDP / Manual / Whitelist / BlockLog / EgressLog)
	core := bootstrap.InitCore(cfg, dbConn)
	defer core.XDP.Close()
	defer func() {
		if core.TcEgress != nil {
			core.TcEgress.Close()
		}
	}()
	defer func() {
		if core.EgressLogMgr != nil {
			core.EgressLogMgr.Close()
		}
	}()

	if err := core.XDP.Start(); err != nil {
		logger.Fatalf("[XDP] Failed to start: %v", err)
	}
	go core.XDP.MonitorBlockLogEvents()

	// 启动 TC Egress 限速程序（可选，不影响主流程）
	if err := core.TcEgress.Start(cfg.EgressLimit); err != nil {
		logger.Warnf("[TcEgress] Failed to start: %v (continuing without egress rate limiting)", err)
	}
	go core.TcEgress.MonitorDropEvents()

	// 加载持久化的缓存规则到 eBPF map（必须在 Start 之后）
	core.LoadCachedRules(cfg)

	// Phase 3: 检测模块工厂 (Intel / Geo / WAF / RateLimit / FailGuard)
	detectors := bootstrap.InitDetectors(cfg, core.XDP, ctx, dbConn, core.WhitelistManager.Checker())

	// 注入 GeoLookup 到 BlockLog 模块（用于 IP 归属地补全）
	core.BlockLogMgr.SetGeoLookup(detectors.GeoMgr, cfg.BlockLog.GeoEnrich)

	// Phase 4: 异常检测
	anomaly := bootstrap.InitAnomaly(cfg, core.XDP, dbConn, core.WhitelistManager.Checker())

	// Phase 5: 认证系统 (Casbin / JWT / Captcha)
	auth := bootstrap.InitAuth(cfg, dbs.AuthDB)

	// 初始化 API Keys from config（依赖 Enforcer）
	if err := dbs.AuthDB.InitAPIKeysFromConfig(auth.Enforcer, cfg.Auth.APIKeys); err != nil {
		logger.Warnf("[Auth] Failed to initialize API keys from config: %v", err)
	}

	// Setup router
	if cfg.Log.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(logger.GinLogger(), logger.GinRecovery())
	api := r.Group("/api")

	// Phase 6: 统一路由注册（含 ConfigHandle）
	bootstrap.RegisterAllRoutes(api, core, dbs, detectors, anomaly, auth)

	// Phase 6.5: 注册前端静态文件（SPA fallback）
	frontend.RegisterFrontend(r)

	// Phase 7: 启动 Server + 优雅退出
	bootstrap.StartServer(cfg, r, ctx, cancel, dbs.BizDB)
}
