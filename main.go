package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"rho-aias/internal/auth/captcha"
	"rho-aias/internal/auth/jwt"
	"rho-aias/internal/blocklog"
	"rho-aias/internal/casbin"
	"rho-aias/internal/config"
	"rho-aias/internal/database"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/geoblocking"
	"rho-aias/internal/handles"
	"rho-aias/internal/kernel"
	"rho-aias/internal/manual"
	"rho-aias/internal/routers"
	"rho-aias/internal/services"
	"rho-aias/internal/threatintel"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// Check kernel version before initializing eBPF/XDP
	result, err := kernel.CheckAndValidate()
	if err != nil {
		log.Fatalf("[Kernel] %v", err)
	}

	// Log kernel version info (reusing the result from CheckAndValidate)
	log.Printf("[Kernel] Detected kernel version: %s", result.CurrentVersion)
	if !result.MeetsRecommended {
		log.Printf("[Kernel] Warning: kernel version %s is below recommended version %s",
			result.CurrentVersion, result.RecommendedVersion)
	}

	cfg := config.NewConfig("config.yml")
	log.Println(cfg)
	// Initialize XDP (existing functionality)
	xdp := ebpfs.NewXdp(cfg.Ebpf.InterfaceName)
	defer xdp.Close()
	if err := xdp.Start(); err != nil {
		panic(err)
	}
	go xdp.MonitorEvents()

	// Initialize Manual Cache and Load Manual Rules
	var manualCache *manual.Cache
	if cfg.Manual.Enabled {
		manualCache = manual.NewCache(cfg.Manual.PersistenceDir)

		// Auto-load manual rules on startup
		if cfg.Manual.AutoLoad && manualCache.Exists() {
			cacheData, err := manualCache.Load()
			if err != nil {
				log.Printf("[Manual] Warning: failed to load cache: %v", err)
			} else {
				log.Printf("[Manual] Loading %d rules from cache...", cacheData.RuleCount())
				loaded := 0
				for _, entry := range cacheData.Rules {
					if err := xdp.AddRule(entry.Value); err != nil {
						log.Printf("[Manual] Warning: failed to add rule %s: %v", entry.Value, err)
					} else {
						loaded++
					}
				}
				log.Printf("[Manual] Loaded %d/%d rules from cache", loaded, cacheData.RuleCount())
			}
		}
	}
	manualHandle := handles.NewManualHandle(xdp, manualCache)

	// Initialize Block Log
	var blockLog *blocklog.BlockLog
	if cfg.BlockLog.Enabled {
		// 启用持久化
		blockLogConfig := blocklog.Config{
			Enabled:         cfg.BlockLog.Enabled,
			LogDir:          cfg.BlockLog.LogDir,
			MemoryCacheSize: cfg.BlockLog.MemoryCacheSize,
			BufferSize:      cfg.BlockLog.BufferSize,
			FlushInterval:   time.Duration(cfg.BlockLog.FlushInterval) * time.Second,
		}
		var err error
		blockLog, err = blocklog.NewBlockLogWithPersistence(cfg.BlockLog.MemoryCacheSize, blockLogConfig)
		if err != nil {
			log.Fatalf("Failed to initialize block log with persistence: %v", err)
		}
		log.Printf("[Main] Block log initialized with persistence enabled, log dir: %s", cfg.BlockLog.LogDir)
	} else {
		// 不启用持久化
		blockLog = blocklog.NewBlockLog(10000)
		log.Println("[Main] Block log initialized without persistence")
	}
	defer blockLog.Close()

	xdp.SetCallback(func(srcIP, dstIP, matchType, ruleSource, countryCode string, packetSize uint32) {
		record := blocklog.CreateRecord(srcIP, dstIP, matchType, ruleSource, countryCode, packetSize)
		blockLog.AddRecord(record)
	})
	blockLogHandle := handles.NewBlockLogHandle(blockLog)

	// Initialize Intel Manager (if enabled)
	var intelMgr *threatintel.Manager
	if cfg.Intel.Enabled {
		intelMgr = threatintel.NewManager(&cfg.Intel, xdp)
		if err := intelMgr.Start(); err != nil {
			log.Printf("Warning: Intel manager start failed: %v", err)
		}
		log.Println("[Main] Intelligence module initialized")
		defer intelMgr.Stop()
	}

	// Initialize Geo-Blocking Manager (if enabled)
	var geoMgr *geoblocking.Manager
	if cfg.GeoBlocking.Enabled {
		geoMgr = geoblocking.NewManager(&cfg.GeoBlocking, xdp)
		if err := geoMgr.Start(); err != nil {
			log.Printf("Warning: Geo-blocking manager start failed: %v", err)
		}
		log.Println("[Main] Geo-blocking module initialized")
		defer geoMgr.Stop()
	}

	// Initialize Authentication (if enabled)
	var (
		db             *database.Database
		authService    *services.AuthService
		userService    *services.UserService
		apiKeyService  *services.APIKeyService
		auditService   *services.AuditService
		authHandle     *handles.AuthHandle
		apiKeyHandle   *handles.APIKeyHandle
		userHandle     *handles.UserHandle
		auditHandle    *handles.AuditHandle
		captchaStore   *captcha.MemoryStore
		casbinEnforcer *casbin.Enforcer
	)
	if cfg.Auth.Enabled {
		// Initialize database
		dbPath := cfg.Auth.DatabasePath
		if dbPath == "" {
			dbPath = "./data/auth.db"
		}
		db, err = database.NewDatabase(dbPath)
		if err != nil {
			log.Fatalf("Failed to initialize database: %v", err)
		}
		defer db.Close()

		// Auto migrate
		if err := db.AutoMigrate(); err != nil {
			log.Fatalf("Failed to migrate database: %v", err)
		}

		// Initialize Casbin
		casbinEnforcer, err = casbin.NewEnforcer(db.DB)
		if err != nil {
			log.Fatalf("Failed to initialize casbin: %v", err)
		}

		// Initialize default policies
		if err := casbinEnforcer.InitDefaultPolicies(); err != nil {
			log.Printf("Warning: failed to initialize default policies: %v", err)
		}

		// Initialize default admin
		if err := db.InitDefaultUser(casbinEnforcer); err != nil {
			log.Printf("Warning: failed to initialize default user: %v", err)
		}

		// Initialize services
		jwtSecret := cfg.Auth.JWTSecret
		if jwtSecret == "" {
			jwtSecret = os.Getenv("JWT_SECRET")
			if jwtSecret == "" {
				jwtSecret = "default-secret-change-me" // 生产环境必须设置
				log.Println("[Auth] Warning: using default JWT secret, please set in config or env")
			}
		}

		jwtService := jwt.NewJWTService(
			jwtSecret,
			time.Duration(cfg.Auth.TokenDuration)*time.Minute,
			cfg.Auth.JWTIssuer,
		)

		authService = services.NewAuthService(db.DB, jwtService)
		userService = services.NewUserService(db.DB)
		apiKeyService = services.NewAPIKeyService(db.DB, casbinEnforcer)
		auditService = services.NewAuditService(db.DB)

		// Initialize captcha
		captchaStore = captcha.NewMemoryStore()
		captchaService := captcha.NewCaptchaService(
			captchaStore,
			time.Duration(cfg.Auth.CaptchaDuration)*time.Minute,
		)

		authHandle = handles.NewAuthHandle(authService, userService, captchaService)
		apiKeyHandle = handles.NewAPIKeyHandle(apiKeyService, auditService)
		userHandle = handles.NewUserHandle(userService, auditService, casbinEnforcer)
		auditHandle = handles.NewAuditHandle(auditService)

		log.Println("[Main] Authentication module initialized")
	}

	// Setup router and routes
	r := gin.Default()
	api := r.Group("/api")

	// Register Auth routes (if enabled)
	if cfg.Auth.Enabled && authHandle != nil {
		routers.RegisterAuthRoutes(api, authHandle, authService, apiKeyService, casbinEnforcer)
	}

	// Register protected routes
	if cfg.Auth.Enabled && authService != nil && apiKeyService != nil && casbinEnforcer != nil {
		// Register API Key management routes
		if apiKeyHandle != nil {
			routers.RegisterAPIKeyRoutes(api, apiKeyHandle, casbinEnforcer, authService, apiKeyService)
		}

		// Register User management routes
		if userHandle != nil {
			routers.RegisterUserRoutes(api, userHandle, casbinEnforcer, authService, apiKeyService)
		}

		// Register Audit log routes
		if auditHandle != nil {
			routers.RegisterAuditRoutes(api, auditHandle, casbinEnforcer, authService, apiKeyService)
		}

		// Register protected routes with Casbin middleware
		routers.RegisterManualRoutes(api, manualHandle, casbinEnforcer, authService, apiKeyService)
		routers.RegisterBlockLogRoutes(api, blockLogHandle, casbinEnforcer, authService, apiKeyService)

		// Register Event Reporting routes
		eventHandle := handles.NewEventHandle(xdp)
		routers.RegisterEventRoutes(api, eventHandle, casbinEnforcer, authService, apiKeyService)

		// Register Intel routes (if enabled)
		if cfg.Intel.Enabled && intelMgr != nil {
			intelHandle := handles.NewIntelHandle(intelMgr)
			routers.RegisterIntelRoutes(api, intelHandle, casbinEnforcer, authService, apiKeyService)
		}

		// Register Geo-Blocking routes (if enabled)
		if cfg.GeoBlocking.Enabled && geoMgr != nil {
			geoHandle := handles.NewGeoBlockingHandle(geoMgr)
			routers.RegisterGeoBlockingRoutes(api, geoHandle, casbinEnforcer, authService, apiKeyService)
		}
	} else {
		// No authentication, register routes directly
		routers.RegisterManualRoutes(api, manualHandle, nil, nil, nil)
		routers.RegisterBlockLogRoutes(api, blockLogHandle, nil, nil, nil)

		// Register Event Reporting routes
		eventHandle := handles.NewEventHandle(xdp)
		routers.RegisterEventRoutes(api, eventHandle, nil, nil, nil)

		if cfg.Intel.Enabled && intelMgr != nil {
			intelHandle := handles.NewIntelHandle(intelMgr)
			routers.RegisterIntelRoutes(api, intelHandle, nil, nil, nil)
		}

		if cfg.GeoBlocking.Enabled && geoMgr != nil {
			geoHandle := handles.NewGeoBlockingHandle(geoMgr)
			routers.RegisterGeoBlockingRoutes(api, geoHandle, nil, nil, nil)
		}
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: r,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Gin服务启动失败: %v", err)
		}
	}()
	log.Printf("Gin服务已启动，监听端口: %d\n", cfg.Server.Port)

	// ----------优雅退出处理----------
	// 创建信号通道
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// 等待信号
	sig := <-quit
	log.Printf("接收到信号: %v，开始优雅退出...\n", sig)

	// 停止情报管理器

	// ebpf由defer关闭
	// 优雅关闭Gin服务（设置超时时间，避免无限等待）
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Gin服务优雅关闭失败: %v", err)
	}
}
