package bootstrap

import (
	"time"

	"rho-aias/internal/blocklog"
	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/egresslog"
	"rho-aias/internal/logger"
	"rho-aias/internal/manual"

	"gorm.io/gorm"
)

// CoreDependencies 核心基础设施初始化结果
type CoreDependencies struct {
	XDP              *ebpfs.Xdp
	TcEgress         *ebpfs.TcEgress
	BlacklistManager *manual.BlacklistManager
	WhitelistManager *manual.WhitelistManager
	BlockLogMgr      *blocklog.Manager
	EgressLogMgr     *egresslog.Manager
}

// InitCore 初始化核心 eBPF 基础设施（不加载缓存规则，缓存需在 Start 后通过 LoadCachedRules 加载）
func InitCore(cfg *config.Config, dbConn *gorm.DB) *CoreDependencies {
	xdp := ebpfs.NewXdp(cfg.Ebpf.InterfaceName)
	tcEgress := ebpfs.NewTcEgress(cfg.Ebpf.InterfaceName)

	manual.InitProtectedNets(logger.Infof)
	whitelistChecker := manual.NewWhitelistChecker()

	blacklistCache := manual.NewCache(cfg.Manual.PersistenceDir)
	whitelistCache := manual.NewCache(cfg.Manual.PersistenceDir)

	blacklistManager := manual.NewBlacklistManager(xdp, blacklistCache, whitelistChecker)
	whitelistManager := manual.NewWhitelistManager(xdp, whitelistCache, whitelistChecker)

	var blockLogMgr *blocklog.Manager
	{
		blConfig := blocklog.Config{
			BufferSize:    cfg.BlockLog.BufferSize,
			FlushInterval: time.Duration(cfg.BlockLog.FlushInterval) * time.Second,
		}
		var err error
		blockLogMgr, err = blocklog.NewManagerWithPersistence(blConfig, dbConn)
		if err != nil {
			logger.Fatalf("[BlockLog] Failed to initialize with persistence: %v", err)
		}
		logger.Info("[Main] Block log initialized with SQLite persistence enabled")
	}

	xdp.SetCallback(func(srcIP, dstIP, matchType, ruleSource, countryCode string, dstPort uint16, packetSize uint32) {
		record := blocklog.CreateRecord(srcIP, dstIP, matchType, ruleSource, countryCode, dstPort, packetSize)
		blockLogMgr.AddRecord(record)
	})

	var egressLogMgr *egresslog.Manager
	{
		elConfig := egresslog.Config{
			BufferSize:    1000,
			FlushInterval: 5 * time.Second,
		}
		var err error
		egressLogMgr, err = egresslog.NewManagerWithPersistence(elConfig, dbConn)
		if err != nil {
			logger.Fatalf("[EgressLog] Failed to initialize with persistence: %v", err)
		}
		logger.Info("[Main] Egress log initialized with SQLite persistence enabled")
	}

	tcEgress.SetDropCallback(func(dstIP string, pktLen uint32, tokens uint64, rateBytes uint64) {
		record := egresslog.CreateDropRecord(dstIP, pktLen, tokens, rateBytes)
		egressLogMgr.AddRecord(record)
		logger.Debugf("[EgressLog] Drop: dstIP=%s, pktLen=%d, tokens=%d, rateBytes=%d", dstIP, pktLen, tokens, rateBytes)
	})

	return &CoreDependencies{
		XDP:              xdp,
		TcEgress:         tcEgress,
		BlacklistManager: blacklistManager,
		WhitelistManager: whitelistManager,
		BlockLogMgr:      blockLogMgr,
		EgressLogMgr:     egressLogMgr,
	}
}

// LoadCachedRules 在 XDP.Start() 之后加载持久化的缓存规则到 eBPF map
func (c *CoreDependencies) LoadCachedRules(cfg *config.Config) {

	// 将内置保护网段写入 eBPF 白名单 map（防止内核层误封云平台元数据/内网服务）
	protectedNets := manual.ProtectedNets()
	for _, ipNet := range protectedNets {
		if err := c.XDP.AddWhitelistRule(ipNet.String()); err != nil {
			logger.Warnf("[Whitelist] Failed to add protected net %s to eBPF whitelist: %v", ipNet.String(), err)
		} else {
			logger.Infof("[Whitelist] Added protected net %s to eBPF whitelist", ipNet.String())
		}
	}

	// 加载手动阻断规则
	blacklistCache := c.BlacklistManager.Cache()
	if blacklistCache != nil && blacklistCache.DataExists(manual.CacheFileBlacklist) {
		cacheData, err := blacklistCache.LoadData(manual.CacheFileBlacklist)
		if err != nil {
			logger.Warnf("[Manual] Failed to load cache: %v", err)
		} else if cacheData.RuleCount() > 0 {
			logger.Infof("[Manual] Loading %d rules from cache...", cacheData.RuleCount())
			loaded := 0
			for _, entry := range cacheData.Rules {
				if err := c.XDP.AddRule(entry.Value); err != nil {
					logger.Warnf("[Manual] Failed to add rule %s: %v", entry.Value, err)
				} else {
					loaded++
				}
			}
			logger.Infof("[Manual] Loaded %d/%d rules from cache", loaded, cacheData.RuleCount())
		}
	}

	// 加载白名单规则
	whitelistCache := c.WhitelistManager.Cache()
	if whitelistCache != nil &&
		cfg.Manual.AutoLoad && whitelistCache.DataExists(manual.CacheFileWhitelist) {
		whitelistData, err := whitelistCache.LoadData(manual.CacheFileWhitelist)
		if err != nil {
			logger.Warnf("[Whitelist] Failed to load cache: %v", err)
		} else if whitelistData.RuleCount() > 0 {
			logger.Infof("[Whitelist] Loading %d rules from cache...", whitelistData.RuleCount())
			loaded := 0
			for _, entry := range whitelistData.Rules {
				if err := c.XDP.AddWhitelistRule(entry.Value); err != nil {
					logger.Warnf("[Whitelist] Failed to add whitelist rule %s: %v", entry.Value, err)
				} else {
					loaded++
				}
			}
			logger.Infof("[Whitelist] Loaded %d/%d rules from cache", loaded, whitelistData.RuleCount())
			c.WhitelistManager.Checker().LoadFromCache(whitelistData)
		}
	}

	// 恢复 blocklog_events 动态配置（由 loadDynamicConfigFromDB 写入 cfg.BlockLog 扩展字段）
	if cfg.BlockLog.EventsEnabled || cfg.BlockLog.EventsSampleRate > 0 {
		sampleRate := cfg.BlockLog.EventsSampleRate
		if sampleRate == 0 {
			sampleRate = 1
		}
		if err := c.XDP.SetBlocklogEventConfig(cfg.BlockLog.EventsEnabled, sampleRate); err != nil {
			logger.Warnf("[BlockLog] Failed to restore blocklog_events config: %v", err)
		} else {
			logger.Infof("[BlockLog] Restored blocklog_events config: enabled=%v, sample_rate=%d",
				cfg.BlockLog.EventsEnabled, sampleRate)
		}
	}

	// 恢复 egress_limit 动态配置（由 loadDynamicConfigFromDB 写入 cfg.EgressLimit 扩展字段）
	if c.TcEgress != nil {
		if cfg.EgressLimit.Enabled || cfg.EgressLimit.RateMbps > 0 {
			egressCfg := ebpfs.EgressLimitConfig{
				Enabled:    0,
				BurstBytes: cfg.EgressLimit.BurstBytes,
			}
			if cfg.EgressLimit.Enabled {
				egressCfg.Enabled = 1
				egressCfg.RateBytes = uint64(cfg.EgressLimit.RateMbps * 1000000 / 8)
			}
			if err := c.TcEgress.SetEgressLimitConfig(egressCfg); err != nil {
				logger.Warnf("[EgressLimit] Failed to restore config: %v", err)
			} else {
				logger.Infof("[EgressLimit] Restored config: enabled=%v, rate=%.1f Mbps, burst=%d bytes",
					cfg.EgressLimit.Enabled, cfg.EgressLimit.RateMbps, cfg.EgressLimit.BurstBytes)
			}
		}

		// 恢复丢包日志配置
		if cfg.EgressLimit.DropLogEnabledRuntime || cfg.EgressLimit.DropLogSampleRateRuntime > 0 {
			sampleRate := cfg.EgressLimit.DropLogSampleRateRuntime
			if sampleRate == 0 {
				sampleRate = 100
			}
			if err := c.TcEgress.SetDropLogConfig(cfg.EgressLimit.DropLogEnabledRuntime, sampleRate); err != nil {
				logger.Warnf("[EgressLimit] Failed to restore drop log config: %v", err)
			} else {
				logger.Infof("[EgressLimit] Restored drop log config: enabled=%v, sample_rate=%d",
					cfg.EgressLimit.DropLogEnabledRuntime, sampleRate)
			}
		}
	}
}
