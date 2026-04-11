package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"rho-aias/internal/anomaly"
	"rho-aias/internal/auth/captcha"
	"rho-aias/internal/auth/jwt"
	"rho-aias/internal/blocklog"
	"rho-aias/internal/casbin"
	"rho-aias/internal/config"
	"rho-aias/internal/database"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/failguard"
	"rho-aias/internal/geoblocking"
	"rho-aias/internal/handles"
	"rho-aias/internal/kernel"
	"rho-aias/internal/logger"
	"rho-aias/internal/manual"
	"rho-aias/internal/models"
	"rho-aias/internal/ratelimit"
	"rho-aias/internal/routers"
	"rho-aias/internal/services"
	"rho-aias/internal/threatintel"
	"rho-aias/internal/waf"
	"rho-aias/internal/watcher"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "config/config.yml", "Path to configuration file")
	flag.Parse()

	// Create main context for managing goroutine lifecycles
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure context is cancelled on exit

	// Check kernel version before initializing eBPF/XDP
	result, err := kernel.CheckAndValidate()
	if err != nil {
		// 初始化日志前无法记录，直接 panic
		panic(fmt.Sprintf("[Kernel] %v", err))
	}

	cfg, err := config.NewConfig(*configPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}

	// Initialize logger
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

	// Log kernel version info
	logger.Infof("[Kernel] Detected kernel version: %s", result.CurrentVersion)
	if !result.MeetsRecommended {
		logger.Warnf("[Kernel] kernel version %s is below recommended version %s",
			result.CurrentVersion, result.RecommendedVersion)
	}

	logger.Debugf("Loaded config: %+v", cfg)
	// Initialize XDP (existing functionality)
	xdp := ebpfs.NewXdp(cfg.Ebpf.InterfaceName)
	defer xdp.Close()
	if err := xdp.Start(); err != nil {
		logger.Fatalf("[XDP] Failed to start: %v", err)
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
				logger.Warnf("[Manual] Failed to load cache: %v", err)
			} else {
				logger.Infof("[Manual] Loading %d rules from cache...", cacheData.RuleCount())
				loaded := 0
				for _, entry := range cacheData.Rules {
					if err := xdp.AddRule(entry.Value); err != nil {
						logger.Warnf("[Manual] Failed to add rule %s: %v", entry.Value, err)
					} else {
						loaded++
					}
				}
				logger.Infof("[Manual] Loaded %d/%d rules from cache", loaded, cacheData.RuleCount())
			}
		}
	}
	manualHandle := handles.NewManualHandle(xdp, manualCache, nil)

	// Initialize Whitelist Cache and Load Whitelist Rules
	var whitelistCache *manual.Cache
	var whitelistHandle *handles.WhitelistHandle
	// 初始化保护网段（包含本机 IP）并记录日志
	manual.InitProtectedNets(logger.Infof)
	whitelistChecker := manual.NewWhitelistChecker()
	if cfg.Manual.Enabled {
		whitelistCache = manual.NewCache(cfg.Manual.PersistenceDir)

		// Auto-load whitelist rules on startup
		if cfg.Manual.AutoLoad && whitelistCache.WhitelistExists() {
			whitelistData, err := whitelistCache.LoadWhitelist()
			if err != nil {
				logger.Warnf("[Whitelist] Failed to load cache: %v", err)
			} else {
				logger.Infof("[Whitelist] Loading %d rules from cache...", whitelistData.WhitelistRuleCount())
				loaded := 0
				for _, entry := range whitelistData.Rules {
					if err := xdp.AddWhitelistRule(entry.Value); err != nil {
						logger.Warnf("[Whitelist] Failed to add rule %s: %v", entry.Value, err)
					} else {
						loaded++
					}
				}
				logger.Infof("[Whitelist] Loaded %d/%d rules from cache", loaded, whitelistData.WhitelistRuleCount())

				// 同步白名单到用户态检查器
				whitelistChecker.LoadFromCache(whitelistData)
				logger.Infof("[Whitelist] User-space whitelist checker loaded with %d exact IPs, %d CIDRs",
					len(whitelistData.Rules), 0)
			}
		}
	}
	whitelistHandle = handles.NewWhitelistHandle(xdp, whitelistCache, whitelistChecker)

	// 将白名单检查器注入手动封禁模块，防止手动封禁白名单 IP
	manualHandle.SetWhitelistChecker(whitelistChecker)

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
			logger.Fatalf("[BlockLog] Failed to initialize with persistence: %v", err)
		}
		logger.Infof("[Main] Block log initialized with persistence enabled, log dir: %s", cfg.BlockLog.LogDir)
	} else {
		// 不启用持久化
		blockLog = blocklog.NewBlockLog(10000)
		logger.Info("[Main] Block log initialized without persistence")
	}
	defer blockLog.Close()

	xdp.SetCallback(func(srcIP, dstIP, matchType, ruleSource, countryCode string, packetSize uint32) {
		record := blocklog.CreateRecord(srcIP, dstIP, matchType, ruleSource, countryCode, packetSize)
		blockLog.AddRecord(record)
	})
	blockLogHandle := handles.NewBlockLogHandle(blockLog)

	// Initialize databases
	// Auth database (for User, APIKey, AuditLog) - mandatory
	var authDB *database.Database
	authDB, err = database.NewDatabase(cfg.Auth.DatabasePath, cfg.Log.Level == "debug")
	if err != nil {
		logger.Fatalf("[Main] Failed to initialize auth database (authentication is mandatory): %v", err)
	}

	// Business database (for BanRecord, SourceStatusRecord)
	var bizDB *database.Database
	bizDB, err = database.NewDatabase(cfg.Business.DatabasePath, cfg.Log.Level == "debug")
	if err != nil {
		logger.Warnf("[Main] Failed to initialize business database: %v (status recording will be disabled)", err)
	}

	// Auto migrate auth tables
	if err := authDB.AutoMigrateAuth(); err != nil {
		logger.Warnf("[Main] Failed to migrate auth database: %v", err)
	}

	// Auto migrate business tables
	if bizDB != nil {
		if err := bizDB.AutoMigrateBusiness(); err != nil {
			logger.Warnf("[Main] Failed to migrate business database: %v", err)
		}

		// 启动时将所有 active 状态的封禁记录标记为 auto_unblock
		// 因为 eBPF map 状态在重启后丢失
		banRecordService := services.NewBanRecordService(bizDB.DB)
		if count, err := banRecordService.MarkAllActiveAsAutoUnblock(); err != nil {
			logger.Warnf("[Main] Failed to mark active bans as auto_unblock: %v", err)
		} else if count > 0 {
			logger.Infof("[Main] Marked %d active ban records as auto_unblock (eBPF state lost on restart)", count)
		}

		// 加载 DB 中的动态配置覆盖 YAML 值
		dynamicConfigService := services.NewDynamicConfigService(bizDB.DB)
		loadDynamicConfigFromDB(dynamicConfigService, cfg)
	}

	// Initialize Intel Manager (if enabled)
	var intelMgr *threatintel.Manager
	var dbConn *gorm.DB
	if bizDB != nil {
		dbConn = bizDB.DB
	}
	if cfg.Intel.Enabled {
		intelMgr = threatintel.NewManager(&cfg.Intel, xdp, dbConn)
		if err := intelMgr.Start(); err != nil {
			logger.Warnf("[Main] Intel manager start failed: %v", err)
		}
		logger.Info("[Main] Intelligence module initialized")
		defer intelMgr.Stop()

		// 启动时自动触发更新（如果配置启用）
		if cfg.Intel.AutoRefreshOnStart {
			go func() {
				select {
				case <-ctx.Done():
					logger.Info("[ThreatIntel] Auto-refresh goroutine cancelled")
					return
				case <-time.After(2 * time.Second):
					// 等待服务完全启动
					logger.Info("[ThreatIntel] Auto-refresh on startup triggered")
					if err := intelMgr.TriggerUpdate(); err != nil {
						logger.Errorf("[ThreatIntel] Auto-refresh failed: %v", err)
					}
				}
			}()
		}
	}

	// Initialize Geo-Blocking Manager (if enabled)
	var geoMgr *geoblocking.Manager
	if cfg.GeoBlocking.Enabled {
		geoMgr = geoblocking.NewManager(&cfg.GeoBlocking, xdp, dbConn)
		if err := geoMgr.Start(); err != nil {
			logger.Warnf("[Main] Geo-blocking manager start failed: %v", err)
		}
		logger.Info("[Main] Geo-blocking module initialized")
		defer geoMgr.Stop()

		// 启动时自动触发更新（如果配置启用）
		if cfg.GeoBlocking.AutoRefreshOnStart {
			go func() {
				select {
				case <-ctx.Done():
					logger.Info("[GeoBlocking] Auto-refresh goroutine cancelled")
					return
				case <-time.After(2 * time.Second):
					// 等待服务完全启动
					logger.Info("[GeoBlocking] Auto-refresh on startup triggered")
					if err := geoMgr.TriggerUpdate(); err != nil {
						logger.Errorf("[GeoBlocking] Auto-refresh failed: %v", err)
					}
				}
			}()
		}
	}

	// Initialize WAF Monitor (if enabled)
	var wafMonitor *waf.Monitor
	if cfg.WAF.Enabled {
		wafMonitor = waf.NewMonitor(&cfg.WAF, xdp, ctx)
		wafMonitor.SetOffsetStore(watcher.NewOffsetStore(cfg.WAF.OffsetStateFile))
		wafMonitor.SetWhitelistCheck(whitelistChecker.IsWhitelisted)
		if bizDB != nil {
			banRecordService := services.NewBanRecordService(bizDB.DB)
			wafMonitor.SetBanRecordStore(banRecordService)
		}
		if err := wafMonitor.Start(); err != nil {
			logger.Warnf("[Main] WAF monitor start failed: %v", err)
		} else {
			logger.Info("[Main] WAF monitor module initialized")
			defer wafMonitor.Stop()
		}
	}

	// Initialize Rate Limit Monitor (if enabled)
	var rateLimitMonitor *ratelimit.Monitor
	if cfg.RateLimit.Enabled {
		rateLimitMonitor = ratelimit.NewMonitor(&cfg.RateLimit, xdp, ctx)
		rateLimitMonitor.SetOffsetStore(watcher.NewOffsetStore(cfg.RateLimit.OffsetStateFile))
		rateLimitMonitor.SetWhitelistCheck(whitelistChecker.IsWhitelisted)
		if bizDB != nil {
			banRecordService := services.NewBanRecordService(bizDB.DB)
			rateLimitMonitor.SetBanRecordStore(banRecordService)
		}
		if err := rateLimitMonitor.Start(); err != nil {
			logger.Warnf("[Main] Rate Limit monitor start failed: %v", err)
		} else {
			logger.Info("[Main] Rate Limit monitor module initialized")
			defer rateLimitMonitor.Stop()
		}
	}

	// Initialize FailGuard (SSH anti-brute-force) Monitor (if enabled)
	var failguardMonitor *failguard.Monitor
	if cfg.FailGuard.Enabled {
		failguardMonitor = failguard.NewMonitor(&cfg.FailGuard, xdp, ctx)
		failguardMonitor.SetOffsetStore(watcher.NewOffsetStore(cfg.FailGuard.OffsetStateFile))
		failguardMonitor.SetWhitelistCheck(whitelistChecker.IsWhitelisted)
		if bizDB != nil {
			banRecordService := services.NewBanRecordService(bizDB.DB)
			failguardMonitor.SetBanRecordStore(banRecordService)
		}
		if err := failguardMonitor.Start(); err != nil {
			logger.Warnf("[Main] FailGuard monitor start failed: %v", err)
		} else {
			logger.Info("[Main] FailGuard module initialized")
			defer failguardMonitor.Stop()
		}
	}

	// Initialize Anomaly Detection (if enabled)
	var anomalyDetector *anomaly.Detector
	if cfg.AnomalyDetection.Enabled {
		// 创建异常检测配置
		anomalyConfig := anomaly.AnomalyDetectionConfig{
			Enabled:         cfg.AnomalyDetection.Enabled,
			SampleRate:      cfg.AnomalyDetection.SampleRate,
			CheckInterval:   cfg.AnomalyDetection.CheckInterval,
			MinPackets:      cfg.AnomalyDetection.MinPackets,
			CleanupInterval: cfg.AnomalyDetection.CleanupInterval,
			Baseline: anomaly.BaselineConfig{
				MinSampleCount:  cfg.AnomalyDetection.Baseline.MinSampleCount,
				SigmaMultiplier: cfg.AnomalyDetection.Baseline.SigmaMultiplier,
				MinThreshold:    cfg.AnomalyDetection.Baseline.MinThreshold,
				MaxAge:          cfg.AnomalyDetection.Baseline.MaxAge,
				BlockDuration:   cfg.AnomalyDetection.Baseline.BlockDuration,
			},
			Attacks: anomaly.AttacksConfig{
				SynFlood: anomaly.AttackConfig{
					Enabled:        cfg.AnomalyDetection.Attacks.SynFlood.Enabled,
					RatioThreshold: cfg.AnomalyDetection.Attacks.SynFlood.RatioThreshold,
					BlockDuration:  cfg.AnomalyDetection.Attacks.SynFlood.BlockDuration,
					MinPackets:     cfg.AnomalyDetection.Attacks.SynFlood.MinPackets,
				},
				UdpFlood: anomaly.AttackConfig{
					Enabled:        cfg.AnomalyDetection.Attacks.UdpFlood.Enabled,
					RatioThreshold: cfg.AnomalyDetection.Attacks.UdpFlood.RatioThreshold,
					BlockDuration:  cfg.AnomalyDetection.Attacks.UdpFlood.BlockDuration,
					MinPackets:     cfg.AnomalyDetection.Attacks.UdpFlood.MinPackets,
				},
				IcmpFlood: anomaly.AttackConfig{
					Enabled:        cfg.AnomalyDetection.Attacks.IcmpFlood.Enabled,
					RatioThreshold: cfg.AnomalyDetection.Attacks.IcmpFlood.RatioThreshold,
					BlockDuration:  cfg.AnomalyDetection.Attacks.IcmpFlood.BlockDuration,
					MinPackets:     cfg.AnomalyDetection.Attacks.IcmpFlood.MinPackets,
				},
				AckFlood: anomaly.AttackConfig{
					Enabled:        cfg.AnomalyDetection.Attacks.AckFlood.Enabled,
					RatioThreshold: cfg.AnomalyDetection.Attacks.AckFlood.RatioThreshold,
					BlockDuration:  cfg.AnomalyDetection.Attacks.AckFlood.BlockDuration,
					MinPackets:     cfg.AnomalyDetection.Attacks.AckFlood.MinPackets,
				},
			},
		}

		// 创建封禁回调函数
		blockCallback := func(ip string, duration int, reason string) error {
			// 白名单检查：跳过白名单 IP
			if whitelistChecker.IsWhitelisted(ip) {
				logger.Infof("[AnomalyDetection] IP %s is whitelisted, skipping block", ip)
				return nil
			}

			// 使用 Anomaly Detection 来源掩码
			err := xdp.AddRuleWithSourceAndExpiry(ip, ebpfs.SourceMaskAnomaly, duration)
			if err != nil {
				logger.Errorf("[AnomalyDetection] Failed to block IP %s: %v", ip, err)
				return err
			}
			// 持久化封禁记录到数据库
			if bizDB != nil {
				banRecordService := services.NewBanRecordService(bizDB.DB)
				if err := banRecordService.UpsertActiveBan(ip, models.BanSourceAnomaly, reason, duration); err != nil {
					logger.Warnf("[AnomalyDetection] Failed to persist ban record for IP %s: %v", ip, err)
				}
			}
			logger.Infof("[AnomalyDetection] Blocked IP %s for %ds, reason: %s", ip, duration, reason)
			return nil
		}

		// 创建解封回调函数
		unblockCallback := func(ip string) error {
			// 移除 Anomaly Detection 来源位，如果规则无其他来源则自动删除
			_, _, _, err := xdp.UpdateRuleSourceMask(ip, ebpfs.SourceMaskAnomaly)
			if err != nil {
				logger.Warnf("[AnomalyDetection] Failed to unblock IP %s: %v", ip, err)
				return err
			}
			// 更新数据库中的封禁状态为已过期
			if bizDB != nil {
				banRecordService := services.NewBanRecordService(bizDB.DB)
				if err := banRecordService.MarkExpired(ip, models.BanSourceAnomaly); err != nil {
					logger.Warnf("[AnomalyDetection] Failed to mark ban record expired for IP %s: %v", ip, err)
				}
			}
			logger.Infof("[AnomalyDetection] Unblocked IP %s (ban expired)", ip)
			return nil
		}

		anomalyDetector = anomaly.NewDetector(anomalyConfig, blockCallback, unblockCallback)
		if err := anomalyDetector.Start(); err != nil {
			logger.Warnf("[Main] Anomaly detector start failed: %v", err)
		} else {
			logger.Info("[Main] Anomaly detection module initialized")
			defer anomalyDetector.Stop()

			// 配置 eBPF 异常检测采样
			if err := xdp.SetAnomalyConfig(true, uint32(cfg.AnomalyDetection.SampleRate)); err != nil {
				logger.Warnf("[Main] Failed to set anomaly config: %v", err)
			}

			// 配置 eBPF 异常检测端口过滤
			ports := make([]uint32, len(cfg.AnomalyDetection.Ports))
			for i, p := range cfg.AnomalyDetection.Ports {
				ports[i] = uint32(p)
			}
			portFilterEnabled := len(ports) > 0
			if err := xdp.SetAnomalyPortFilter(portFilterEnabled, ports); err != nil {
				logger.Warnf("[Main] Failed to set anomaly port filter: %v", err)
			}

			// 启动异常检测事件监听
			go xdp.MonitorAnomalyEvents(func(srcIP string, protocol uint8, tcpFlags uint8, pktSize uint32) {
				anomalyDetector.RecordPacket(srcIP, protocol, tcpFlags, pktSize)
			})
		}
	}

	// Initialize Authentication (mandatory)
	var (
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
	if authDB == nil {
		logger.Fatalf("[Main] Failed to initialize auth database, authentication is mandatory")
		return
	}
	defer authDB.Close()

	// Initialize Casbin
	casbinEnforcer, err = casbin.NewEnforcer(authDB.DB)
	if err != nil {
		logger.Fatalf("[Auth] Failed to initialize casbin: %v", err)
	}

	// Initialize default policies
	if err := casbinEnforcer.InitDefaultPolicies(); err != nil {
		logger.Warnf("[Auth] Failed to initialize default policies: %v", err)
	}

	// Initialize default admin
	if err := authDB.InitDefaultUser(casbinEnforcer); err != nil {
		logger.Warnf("[Auth] Failed to initialize default user: %v", err)
	}

	// Initialize API Keys from config
	if err := authDB.InitAPIKeysFromConfig(casbinEnforcer, cfg.Auth.APIKeys); err != nil {
		logger.Warnf("[Auth] Failed to initialize API keys from config: %v", err)
	}

	// Initialize services
	jwtSecret := cfg.Auth.JWTSecret
	if jwtSecret == "" {
		jwtSecret = os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default-secret-change-me" // 生产环境必须设置
			logger.Warn("[Auth] Using default JWT secret, please set in config or env")
		}
	}

	jwtService := jwt.NewJWTService(
		jwtSecret,
		time.Duration(cfg.Auth.TokenDuration)*time.Minute,
		cfg.Auth.JWTIssuer,
	)

	authService = services.NewAuthService(authDB.DB, jwtService)
	userService = services.NewUserService(authDB.DB)
	apiKeyService = services.NewAPIKeyService(authDB.DB, casbinEnforcer)
	auditService = services.NewAuditService(authDB.DB)

	// Initialize captcha
	captchaStore, err = captcha.NewMemoryStore()
	if err != nil {
		logger.Fatalf("Failed to initialize captcha store: %v", err)
	}
	captchaService := captcha.NewCaptchaService(
		captchaStore,
		time.Duration(cfg.Auth.CaptchaDuration)*time.Minute,
	)

	authHandle = handles.NewAuthHandle(authService, userService, captchaService)
	apiKeyHandle = handles.NewAPIKeyHandle(apiKeyService, auditService)
	userHandle = handles.NewUserHandle(userService, auditService, casbinEnforcer)
	auditHandle = handles.NewAuditHandle(auditService)

	logger.Info("[Main] Authentication module initialized")

	// Setup router and routes
	// Set Gin mode based on log level
	if cfg.Log.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(logger.GinLogger(), logger.GinRecovery())
	api := r.Group("/api")

	// Register Auth routes
	routers.RegisterAuthRoutes(api, authHandle, authService, apiKeyService, casbinEnforcer)

	// Build auth context
	authEnforcer := casbinEnforcer
	authSvc := authService
	apiKeySvc := apiKeyService

	// Register auth-only routes (API Key management, user management, audit)
	if apiKeyHandle != nil {
		routers.RegisterAPIKeyRoutes(api, apiKeyHandle, authEnforcer, authSvc, apiKeySvc)
	}
	if userHandle != nil {
		routers.RegisterUserRoutes(api, userHandle, authEnforcer, authSvc, apiKeySvc)
	}
	if auditHandle != nil {
		routers.RegisterAuditRoutes(api, auditHandle, authEnforcer, authSvc, apiKeySvc)
	}

	// Register common routes (all have built-in nil guards for authEnforcer/authSvc/apiKeySvc)
	routers.RegisterManualRoutes(api, manualHandle, authEnforcer, authSvc, apiKeySvc)
	routers.RegisterWhitelistRoutes(api, whitelistHandle, authEnforcer, authSvc, apiKeySvc)
	routers.RegisterBlockLogRoutes(api, blockLogHandle, authEnforcer, authSvc, apiKeySvc)

	ruleQueryHandle := handles.NewRuleQueryHandle(xdp)
	routers.RegisterRuleRoutes(api, ruleQueryHandle, authEnforcer, authSvc, apiKeySvc)

	eventHandle := handles.NewEventHandle(xdp)
	routers.RegisterEventRoutes(api, eventHandle, authEnforcer, authSvc, apiKeySvc)

	if bizDB != nil {
		sourceHandle := handles.NewSourceHandle(bizDB.DB, intelMgr, geoMgr)
		routers.RegisterSourceRoutes(api, sourceHandle, authEnforcer, authSvc, apiKeySvc)
	}

	if cfg.Intel.Enabled && intelMgr != nil {
		intelHandle := handles.NewIntelHandle(intelMgr)
		routers.RegisterIntelRoutes(api, intelHandle, authEnforcer, authSvc, apiKeySvc)
	}

	if cfg.GeoBlocking.Enabled && geoMgr != nil {
		geoHandle := handles.NewGeoBlockingHandle(geoMgr)
		routers.RegisterGeoBlockingRoutes(api, geoHandle, authEnforcer, authSvc, apiKeySvc)
	}

	if bizDB != nil {
		banRecordService := services.NewBanRecordService(bizDB.DB)
		banRecordHandle := handles.NewBanRecordHandle(banRecordService, xdp)
		routers.RegisterBanRecordRoutes(api, banRecordHandle, authEnforcer, authSvc, apiKeySvc)
	}

	// Register unified config routes (dynamic config API)
	if bizDB != nil {
		dynamicConfigService := services.NewDynamicConfigService(bizDB.DB)
		configHandle := handles.NewConfigHandle(
			dynamicConfigService,
			failguardMonitor,
			wafMonitor,
			rateLimitMonitor,
			anomalyDetector,
			geoMgr,
			intelMgr,
		)
		routers.RegisterConfigRoutes(api, configHandle, authEnforcer, authSvc, apiKeySvc)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: r,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("[Server] Gin服务启动失败: %v", err)
		}
	}()
	logger.Infof("[Server] Gin服务已启动，监听端口: %d", cfg.Server.Port)

	// ----------优雅退出处理----------
	// 创建信号通道
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// 等待信号
	sig := <-quit
	logger.Infof("[Main] 接收到信号: %v，开始优雅退出...", sig)

	// 取消所有后台 goroutine
	cancel()
	logger.Info("[Main] 已取消所有后台 goroutine")

	// 停止情报管理器

	// Close business database
	if bizDB != nil {
		if err := bizDB.Close(); err != nil {
			logger.Warnf("[Main] Failed to close business database: %v", err)
		}
	}

	// ebpf由defer关闭
	// 优雅关闭Gin服务（设置超时时间，避免无限等待）
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Fatalf("[Server] Gin服务优雅关闭失败: %v", err)
	}
	logger.Info("[Main] 服务已关闭")

	// Sync logger before exit
	_ = logger.Sync()
}

// loadDynamicConfigFromDB 从数据库加载动态配置覆盖 YAML 值
// 只在启动时调用一次，之后运行时全走 API
func loadDynamicConfigFromDB(svc *services.DynamicConfigService, cfg *config.Config) {
	loaded := make(map[string]string) // module -> "YAML default" or "DB override: {values}"

	// FailGuard
	type failGuardDynamic struct {
		Enabled     bool   `json:"enabled"`
		MaxRetry    int    `json:"max_retry"`
		FindTime    int    `json:"find_time"`
		BanDuration int    `json:"ban_duration"`
		Mode        string `json:"mode"`
	}
	var fg failGuardDynamic
	if ok, err := svc.LoadTo("failguard", &fg); err != nil {
		logger.Warnf("[Main] Failed to load failguard dynamic config from DB: %v", err)
	} else if ok {
		cfg.FailGuard.Enabled = fg.Enabled
		if fg.MaxRetry > 0 {
			cfg.FailGuard.MaxRetry = fg.MaxRetry
		}
		if fg.FindTime > 0 {
			cfg.FailGuard.FindTime = fg.FindTime
		}
		if fg.BanDuration > 0 {
			cfg.FailGuard.BanDuration = fg.BanDuration
		}
		if fg.Mode != "" {
			cfg.FailGuard.Mode = fg.Mode
		}
		loaded["failguard"] = fmt.Sprintf("enabled=%v, max_retry=%d, find_time=%d, ban_duration=%d, mode=%s",
			fg.Enabled, fg.MaxRetry, fg.FindTime, fg.BanDuration, fg.Mode)
	}

	// WAF
	type wafDynamic struct {
		Enabled     bool `json:"enabled"`
		BanDuration int  `json:"ban_duration"`
	}
	var wf wafDynamic
	if ok, err := svc.LoadTo("waf", &wf); err != nil {
		logger.Warnf("[Main] Failed to load waf dynamic config from DB: %v", err)
	} else if ok {
		cfg.WAF.Enabled = wf.Enabled
		if wf.BanDuration > 0 {
			cfg.WAF.BanDuration = wf.BanDuration
		}
		loaded["waf"] = fmt.Sprintf("enabled=%v, ban_duration=%d", wf.Enabled, wf.BanDuration)
	}

	// RateLimit
	type rateLimitDynamic struct {
		Enabled     bool `json:"enabled"`
		BanDuration int  `json:"ban_duration"`
	}
	var rl rateLimitDynamic
	if ok, err := svc.LoadTo("rate_limit", &rl); err != nil {
		logger.Warnf("[Main] Failed to load rate_limit dynamic config from DB: %v", err)
	} else if ok {
		cfg.RateLimit.Enabled = rl.Enabled
		if rl.BanDuration > 0 {
			cfg.RateLimit.BanDuration = rl.BanDuration
		}
		loaded["rate_limit"] = fmt.Sprintf("enabled=%v, ban_duration=%d", rl.Enabled, rl.BanDuration)
	}

	// AnomalyDetection
	type anomalyDynamic struct {
		Enabled    bool                   `json:"enabled"`
		MinPackets int                    `json:"min_packets"`
		Ports      []int                  `json:"ports"`
		Baseline   anomaly.BaselineConfig `json:"baseline"`
		Attacks    anomaly.AttacksConfig  `json:"attacks"`
	}
	var ad anomalyDynamic
	if ok, err := svc.LoadTo("anomaly_detection", &ad); err != nil {
		logger.Warnf("[Main] Failed to load anomaly_detection dynamic config from DB: %v", err)
	} else if ok {
		cfg.AnomalyDetection.Enabled = ad.Enabled
		if ad.MinPackets > 0 {
			cfg.AnomalyDetection.MinPackets = ad.MinPackets
		}
		if len(ad.Ports) > 0 {
			cfg.AnomalyDetection.Ports = ad.Ports
		}
		if ad.Baseline.MinSampleCount > 0 {
			cfg.AnomalyDetection.Baseline = config.BaselineConfig{
				MinSampleCount:  ad.Baseline.MinSampleCount,
				SigmaMultiplier: ad.Baseline.SigmaMultiplier,
				MinThreshold:    ad.Baseline.MinThreshold,
				MaxAge:          ad.Baseline.MaxAge,
				BlockDuration:   ad.Baseline.BlockDuration,
			}
		}
		if ad.Attacks.SynFlood.RatioThreshold > 0 {
			cfg.AnomalyDetection.Attacks = config.AttacksConfig{
				SynFlood: config.AttackConfig{
					Enabled:        ad.Attacks.SynFlood.Enabled,
					RatioThreshold: ad.Attacks.SynFlood.RatioThreshold,
					BlockDuration:  ad.Attacks.SynFlood.BlockDuration,
					MinPackets:     ad.Attacks.SynFlood.MinPackets,
				},
				UdpFlood: config.AttackConfig{
					Enabled:        ad.Attacks.UdpFlood.Enabled,
					RatioThreshold: ad.Attacks.UdpFlood.RatioThreshold,
					BlockDuration:  ad.Attacks.UdpFlood.BlockDuration,
					MinPackets:     ad.Attacks.UdpFlood.MinPackets,
				},
				IcmpFlood: config.AttackConfig{
					Enabled:        ad.Attacks.IcmpFlood.Enabled,
					RatioThreshold: ad.Attacks.IcmpFlood.RatioThreshold,
					BlockDuration:  ad.Attacks.IcmpFlood.BlockDuration,
					MinPackets:     ad.Attacks.IcmpFlood.MinPackets,
				},
				AckFlood: config.AttackConfig{
					Enabled:        ad.Attacks.AckFlood.Enabled,
					RatioThreshold: ad.Attacks.AckFlood.RatioThreshold,
					BlockDuration:  ad.Attacks.AckFlood.BlockDuration,
					MinPackets:     ad.Attacks.AckFlood.MinPackets,
				},
			}
		}
		portsStr := fmt.Sprintf("%v", ad.Ports)
		loaded["anomaly_detection"] = fmt.Sprintf("enabled=%v, min_packets=%d, ports=%s",
			ad.Enabled, ad.MinPackets, portsStr)
	}

	// GeoBlocking
	type geoDynamic struct {
		Enabled          bool     `json:"enabled"`
		Mode             string   `json:"mode"`
		AllowedCountries []string `json:"allowed_countries"`
	}
	var geo geoDynamic
	if ok, err := svc.LoadTo("geo_blocking", &geo); err != nil {
		logger.Warnf("[Main] Failed to load geo_blocking dynamic config from DB: %v", err)
	} else if ok {
		cfg.GeoBlocking.Enabled = geo.Enabled
		if geo.Mode != "" {
			cfg.GeoBlocking.Mode = geo.Mode
		}
		if geo.AllowedCountries != nil {
			cfg.GeoBlocking.AllowedCountries = geo.AllowedCountries
		}
		loaded["geo_blocking"] = fmt.Sprintf("enabled=%v, mode=%s, countries=%v",
			geo.Enabled, geo.Mode, geo.AllowedCountries)
	}

	// Intel
	type intelDynamic struct {
		Enabled bool `json:"enabled"`
	}
	var intel intelDynamic
	if ok, err := svc.LoadTo("intel", &intel); err != nil {
		logger.Warnf("[Main] Failed to load intel dynamic config from DB: %v", err)
	} else if ok {
		cfg.Intel.Enabled = intel.Enabled
		loaded["intel"] = fmt.Sprintf("enabled=%v", intel.Enabled)
	}

	// 输出每个模块的配置来源（便于排查"改了config.yml不生效"的问题）
	modules := []string{"failguard", "waf", "rate_limit", "anomaly_detection", "geo_blocking", "intel"}
	logger.Info("[Main] Dynamic config loaded (DB values override YAML):")
	for _, mod := range modules {
		if val, exists := loaded[mod]; exists {
			logger.Infof("[Main] [DynamicConfig] %-20s → DB override       %s", mod, val)
		} else {
			logger.Infof("[Main] [DynamicConfig] %-20s → YAML default      (no DB record)", mod)
		}
	}
}
