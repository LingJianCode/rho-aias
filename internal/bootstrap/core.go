package bootstrap

import (
	"time"

	"rho-aias/internal/blocklog"
	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/handles"
	"rho-aias/internal/logger"
	"rho-aias/internal/manual"
)

// CoreDependencies 核心基础设施初始化结果
type CoreDependencies struct {
	XDP             *ebpfs.Xdp
	ManualHandle    *handles.BlocklistHandle
	WhitelistHandle *handles.WhitelistHandle
	BlockLogHandle  *handles.BlockLogHandle
}

// InitCore 初始化核心 eBPF 基础设施（不加载缓存规则，缓存需在 Start 后通过 LoadCachedRules 加载）
func InitCore(cfg *config.Config) *CoreDependencies {
	xdp := ebpfs.NewXdp(cfg.Ebpf.InterfaceName)

	var manualCache *manual.Cache
	if cfg.Manual.Enabled {
		manualCache = manual.NewCache(cfg.Manual.PersistenceDir)
	}
	manualHandle := handles.NewBlocklistHandle(xdp, manualCache, nil)

	var whitelistCache *manual.Cache
	var whitelistHandle *handles.WhitelistHandle
	manual.InitProtectedNets(logger.Infof)
	whitelistChecker := manual.NewWhitelistChecker()
	if cfg.Manual.Enabled {
		whitelistCache = manual.NewCache(cfg.Manual.PersistenceDir)
	}
	whitelistHandle = handles.NewWhitelistHandle(xdp, whitelistCache, whitelistChecker)
	manualHandle.SetWhitelistChecker(whitelistChecker)

	var blockLog *blocklog.BlockLog
	{
		blConfig := blocklog.Config{
			LogDir:          cfg.BlockLog.LogDir,
			MemoryCacheSize: cfg.BlockLog.MemoryCacheSize,
			BufferSize:      cfg.BlockLog.BufferSize,
			FlushInterval:   time.Duration(cfg.BlockLog.FlushInterval) * time.Second,
		}
		var err error
		blockLog, err = blocklog.NewBlockLogWithPersistence(cfg.BlockLog.MemoryCacheSize, blConfig)
		if err != nil {
			logger.Fatalf("[BlockLog] Failed to initialize with persistence: %v", err)
		}
		logger.Infof("[Main] Block log initialized with persistence enabled, log dir: %s", cfg.BlockLog.LogDir)
	}

	xdp.SetCallback(func(srcIP, dstIP, matchType, ruleSource, countryCode string, packetSize uint32) {
		record := blocklog.CreateRecord(srcIP, dstIP, matchType, ruleSource, countryCode, packetSize)
		blockLog.AddRecord(record)
	})
	blockLogHandle := handles.NewBlockLogHandle(blockLog, xdp)

	return &CoreDependencies{
		XDP:             xdp,
		ManualHandle:    manualHandle,
		WhitelistHandle: whitelistHandle,
		BlockLogHandle:  blockLogHandle,
	}
}

// LoadCachedRules 在 XDP.Start() 之后加载持久化的缓存规则到 eBPF map
func (c *CoreDependencies) LoadCachedRules(cfg *config.Config) {
	if !cfg.Manual.Enabled {
		return
	}

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
	if c.ManualHandle != nil && c.ManualHandle.Cache() != nil && c.ManualHandle.Cache().DataExists(manual.CacheFileBlocklist) {
		cacheData, err := c.ManualHandle.Cache().LoadData(manual.CacheFileBlocklist)
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
	if c.WhitelistHandle != nil && c.WhitelistHandle.Cache() != nil &&
		cfg.Manual.AutoLoad && c.WhitelistHandle.Cache().DataExists(manual.CacheFileWhitelist) {
		whitelistData, err := c.WhitelistHandle.Cache().LoadData(manual.CacheFileWhitelist)
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
			c.WhitelistHandle.Checker().LoadFromCache(whitelistData)
		}
	}
}
