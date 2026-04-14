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
	ManualHandle    *handles.ManualHandle
	WhitelistHandle *handles.WhitelistHandle
	BlockLogHandle  *handles.BlockLogHandle
}

// InitCore 初始化核心 eBPF 基础设施和规则缓存
func InitCore(cfg *config.Config) *CoreDependencies {
	xdp := ebpfs.NewXdp(cfg.Ebpf.InterfaceName)

	var manualCache *manual.Cache
	if cfg.Manual.Enabled {
		manualCache = manual.NewCache(cfg.Manual.PersistenceDir)
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

	var whitelistCache *manual.Cache
	var whitelistHandle *handles.WhitelistHandle
	manual.InitProtectedNets(logger.Infof)
	whitelistChecker := manual.NewWhitelistChecker()
	if cfg.Manual.Enabled {
		whitelistCache = manual.NewCache(cfg.Manual.PersistenceDir)
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
				whitelistChecker.LoadFromCache(whitelistData)
			}
		}
	}
	whitelistHandle = handles.NewWhitelistHandle(xdp, whitelistCache, whitelistChecker)
	manualHandle.SetWhitelistChecker(whitelistChecker)

	var blockLog *blocklog.BlockLog
	if cfg.BlockLog.Enabled {
		blConfig := blocklog.Config{
			Enabled:         cfg.BlockLog.Enabled,
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
	} else {
		blockLog = blocklog.NewBlockLog(10000)
		logger.Info("[Main] Block log initialized without persistence")
	}

	xdp.SetCallback(func(srcIP, dstIP, matchType, ruleSource, countryCode string, packetSize uint32) {
		record := blocklog.CreateRecord(srcIP, dstIP, matchType, ruleSource, countryCode, packetSize)
		blockLog.AddRecord(record)
	})
	blockLogHandle := handles.NewBlockLogHandle(blockLog)

	return &CoreDependencies{
		XDP:             xdp,
		ManualHandle:    manualHandle,
		WhitelistHandle: whitelistHandle,
		BlockLogHandle:  blockLogHandle,
	}
}
