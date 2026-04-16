// Package geoblocking 地域封禁模块
package geoblocking

import (
	"fmt"
	"sync"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/feed"
	"rho-aias/internal/logger"

	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

// Manager GeoIP 管理器
type Manager struct {
	config  *config.GeoBlockingConfig // GeoBlocking 配置
	xdp     *ebpfs.Xdp                // XDP eBPF 程序接口
	fetcher *feed.Fetcher             // 数据获取器（公共）
	parser  *Parser                   // 数据解析器
	cache   *feed.Cache[CacheData]    // 持久化缓存（公共泛型）
	syncer  *Syncer                   // 内核同步器
	cron    *cron.Cron                // Cron 调度器
	jobIDs  map[SourceID]cron.EntryID // 各源的 Cron 任务 ID
	done    chan struct{}             // 停止信号
	stopOnce sync.Once               // 确保 Stop 只执行一次
	mu      sync.RWMutex              // 读写锁

	// 状态管理
	status       *Status                    // 模块状态
	sourceStatus map[SourceID]*SourceStatus // 各 GeoIP 源状态

	// 数据库支持和并发控制（使用公共组件）
	db            *gorm.DB                  // 数据库连接
	sourceMutexes *feed.MutexPool[SourceID] // 互斥锁池（公共）
}

// NewManager 创建新的 GeoIP 管理器
func NewManager(cfg *config.GeoBlockingConfig, xdp *ebpfs.Xdp, db *gorm.DB) *Manager {
	return &Manager{
		config:        cfg,
		xdp:           xdp,
		fetcher:       feed.NewFetcher(30 * time.Second),
		parser:        NewParser(),
		cache:         feed.NewCache[CacheData](cfg.PersistenceDir, "geoip_cache.bin"),
		syncer:        NewSyncer(xdp, cfg.BatchSize),
		done:          make(chan struct{}),
		sourceStatus:  make(map[SourceID]*SourceStatus),
		db:            db,
		sourceMutexes: feed.NewMutexPool[SourceID](),
		status: &Status{
			Enabled:          cfg.Enabled,
			Mode:             cfg.Mode,
			AllowedCountries: cfg.AllowedCountries,
			Sources:          make(map[SourceID]SourceStatus),
		},
	}
}

// Start 启动 GeoIP 管理器
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		logger.Info("[GeoBlocking] Geo-blocking module is disabled")
		return nil
	}

	logger.Info("[GeoBlocking] Starting geo-blocking manager...")

	// 1. 加载本地缓存（离线启动）
	if err := m.loadFromCache(); err != nil {
		logger.Warnf("[GeoBlocking] Failed to load cache: %v", err)
	} else {
		logger.Info("[GeoBlocking] Loaded cache successfully")
	}

	// 2. 创建 Cron 调度器
	m.cron = cron.New()
	m.jobIDs = make(map[SourceID]cron.EntryID)

	// 3. 为每个启用的源注册独立的 Cron 任务
	for id, src := range m.config.Sources {
		if src.Enabled && src.Periodic {
			if err := m.scheduleSource(SourceID(id), src); err != nil {
				logger.Warnf("[GeoBlocking] Failed to schedule %s: %v", id, err)
			}
		} else if src.Enabled && !src.Periodic {
			logger.Infof("[GeoBlocking] [%s] Periodic update disabled, skipping cron schedule", id)
		}
	}

	// 4. 启动 Cron 调度器
	m.cron.Start()

	logger.Info("[GeoBlocking] Started successfully")
	return nil
}

// updateKernelConfig 更新内核配置
func (m *Manager) updateKernelConfig() error {
	mode := uint32(0)
	if m.status.Mode == "blacklist" {
		mode = 1
	}
	return m.xdp.UpdateGeoConfig(m.config.Enabled, mode)
}

// scheduleSource 为单个源注册 Cron 任务
func (m *Manager) scheduleSource(sourceID SourceID, src config.GeoIPSource) error {
	schedule, err := cron.ParseStandard(src.Schedule)
	if err != nil {
		return fmt.Errorf("invalid cron schedule '%s' for %s: %w", src.Schedule, sourceID, err)
	}

	jobID := m.cron.Schedule(schedule, cron.FuncJob(func() {
		logger.Infof("[GeoBlocking] [%s] Scheduled update triggered", sourceID)
		if err := m.updateSource(sourceID, src); err != nil {
			logger.Errorf("[GeoBlocking] [%s] update failed: %v", sourceID, err)
			m.updateSourceStatus(sourceID, false, 0, err.Error())
		}
		if err := m.saveCache(); err != nil {
			logger.Errorf("[GeoBlocking] Failed to save cache: %v", err)
		}
	}))

	m.jobIDs[sourceID] = jobID

	status, exists := m.sourceStatus[sourceID]
	if !exists {
		status = &SourceStatus{}
		m.sourceStatus[sourceID] = status
	}
	status.Enabled = true
	m.status.Sources[sourceID] = *status

	logger.Infof("[GeoBlocking] [%s] Scheduled with cron: %s", sourceID, src.Schedule)
	return nil
}

// updateAllSources 更新所有启用的 GeoIP 源（用于手动触发）
func (m *Manager) updateAllSources() {
	logger.Info("[GeoBlocking] Starting update for all sources...")

	sources := m.getEnabledSources()
	if len(sources) == 0 {
		logger.Info("[GeoBlocking] No enabled sources")
		return
	}

	for sourceID, src := range sources {
		if err := m.updateSource(sourceID, src); err != nil {
			logger.Errorf("[GeoBlocking] [%s] update failed: %v", sourceID, err)
			m.updateSourceStatus(sourceID, false, 0, err.Error())
		}
	}

	if err := m.saveCache(); err != nil {
		logger.Errorf("[GeoBlocking] Failed to save cache: %v", err)
	}

	logger.Info("[GeoBlocking] Update completed")
}

// updateSource 更新单个 GeoIP 源
func (m *Manager) updateSource(sourceID SourceID, src config.GeoIPSource) error {
	mu := m.sourceMutexes.Get(sourceID)
	if !mu.TryLock() {
		logger.Warnf("[GeoBlocking] [%s] Update skipped - already in progress", sourceID)
		return fmt.Errorf("update already in progress")
	}
	defer mu.Unlock()

	logger.Infof("[GeoBlocking] [%s] Fetching from %s", sourceID, src.URL)
	startTime := time.Now()

	// 1. 获取数据
	data, err := m.fetcher.Fetch(src.URL)
	if err != nil {
		duration := time.Since(startTime).Milliseconds()
		_ = feed.RecordStatus(m.db, feed.SourceTypeGeoBlocking, string(sourceID), string(sourceID), "failed", 0, err.Error(), duration)
		return err
	}
	logger.Infof("[GeoBlocking] [%s] Fetched %d bytes", sourceID, len(data))

	// 2. 解析数据（传递允许的国家列表）
	parsed, err := m.parser.Parse(data, src.Format, m.config.AllowedCountries, sourceID)
	if err != nil {
		duration := time.Since(startTime).Milliseconds()
		_ = feed.RecordStatus(m.db, feed.SourceTypeGeoBlocking, string(sourceID), string(sourceID), "failed", 0, err.Error(), duration)
		return err
	}
	logger.Infof("[GeoBlocking] [%s] Parsed %d rules", sourceID, parsed.TotalCount())

	// 3. 同步到内核
	geoConfig := &GeoConfig{
		Enabled:              m.config.Enabled,
		Mode:                 m.config.Mode,
		AllowedCountries:     m.config.AllowedCountries,
		AllowPrivateNetworks: m.config.AllowPrivateNetworks,
	}
	if err := m.syncer.SyncToKernel(parsed, geoConfig); err != nil {
		duration := time.Since(startTime).Milliseconds()
		_ = feed.RecordStatus(m.db, feed.SourceTypeGeoBlocking, string(sourceID), string(sourceID), "failed", 0, err.Error(), duration)
		return err
	}

	// 4. 更新状态
	m.updateSourceStatus(sourceID, true, parsed.TotalCount(), "")

	// 5. 记录成功状态 + 清理旧记录
	duration := time.Since(startTime).Milliseconds()
	if err := feed.RecordStatus(m.db, feed.SourceTypeGeoBlocking, string(sourceID), string(sourceID), "success", parsed.TotalCount(), "", duration); err != nil {
		logger.Errorf("[GeoBlocking] [%s] Failed to record status to DB: %v", sourceID, err)
	}
	if err := feed.CleanOldRecords(m.db, feed.SourceTypeGeoBlocking, string(sourceID)); err != nil {
		logger.Errorf("[GeoBlocking] [%s] Failed to clean old records: %v", sourceID, err)
	}

	return nil
}

// loadFromCache 从本地缓存加载 GeoIP（离线启动支持）
func (m *Manager) loadFromCache() error {
	if !m.cache.Exists() {
		return ErrGeoIPCacheNotFound
	}

	cacheData, err := m.cache.Load()
	if err != nil {
		return err
	}

	logger.Infof("[GeoBlocking] Loading cache with %d sources...", len(cacheData.Sources))

	now := time.Now()

	for sourceID, data := range cacheData.Sources {
		logger.Infof("[GeoBlocking] [%s] Loading %d rules from cache", sourceID, data.TotalCount())

		geoConfig := &GeoConfig{
			Enabled:              cacheData.Config.Enabled,
			Mode:                 cacheData.Config.Mode,
			AllowedCountries:     cacheData.Config.AllowedCountries,
			AllowPrivateNetworks: m.config.AllowPrivateNetworks,
		}
		if err := m.syncer.LoadAll(&data, geoConfig); err != nil {
			logger.Warnf("[GeoBlocking] [%s] Failed to load from cache: %v", sourceID, err)
			m.setSourceStatusInline(sourceID, false, 0, err.Error())
			continue
		}

		m.setSourceStatusInline(sourceID, true, data.TotalCount(), "")
	}

	// 计算总规则数
	totalRules := 0
	for _, s := range m.sourceStatus {
		totalRules += s.RuleCount
	}
	m.status.TotalRules = totalRules
	m.status.LastUpdate = now

	return nil
}

// setSourceStatusInline 内联更新源状态（避免死锁）
func (m *Manager) setSourceStatusInline(sourceID SourceID, success bool, ruleCount int, errMsg string) {
	now := time.Now()
	status, exists := m.sourceStatus[sourceID]
	if !exists {
		status = &SourceStatus{}
		m.sourceStatus[sourceID] = status
	}

	if success {
		status.SetSuccess(now, ruleCount)
	} else {
		status.SetFailure(now, errMsg)
	}

	m.status.Sources[sourceID] = *status
}

// saveCache 保存 GeoIP 到本地缓存
func (m *Manager) saveCache() error {
	cacheData := NewCacheData()
	cacheData.Config = GeoConfig{
		Enabled:          m.config.Enabled,
		Mode:             m.config.Mode,
		AllowedCountries: m.config.AllowedCountries,
	}

	m.mu.RLock()
	for sourceID, status := range m.sourceStatus {
		if status.Success && status.RuleCount > 0 {
			rules, _ := m.xdp.GetGeoIPRules()
			data := NewGeoIPData(sourceID)

			for _, r := range rules {
				data.AddCIDR(r)
			}
			cacheData.Sources[sourceID] = *data
		}
	}
	m.mu.RUnlock()

	return m.cache.Save(*cacheData)
}

// updateSourceStatus 更新 GeoIP 源状态
func (m *Manager) updateSourceStatus(sourceID SourceID, success bool, ruleCount int, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	status, exists := m.sourceStatus[sourceID]
	if !exists {
		status = &SourceStatus{}
		m.sourceStatus[sourceID] = status
	}

	status.LastUpdate = now
	status.Success = success
	status.RuleCount = ruleCount
	status.Error = errMsg

	m.status.LastUpdate = now

	// 更新公共状态
	m.status.Sources[sourceID] = *status
	m.status.LastUpdate = now

	// 计算总规则数
	totalRules := 0
	for _, s := range m.sourceStatus {
		totalRules += s.RuleCount
	}
	m.status.TotalRules = totalRules
}

// getEnabledSources 获取所有启用的 GeoIP 源配置
func (m *Manager) getEnabledSources() map[SourceID]config.GeoIPSource {
	sources := make(map[SourceID]config.GeoIPSource)

	for sourceID, src := range m.config.Sources {
		if src.Enabled {
			sources[SourceID(sourceID)] = src
		}
	}

	return sources
}

// GetStatus 获取 GeoIP 模块状态（优先查 DB，DB 无记录返回空）
func (m *Manager) GetStatus() *Status {
	m.mu.RLock()
	xdpEnabled := m.xdp.GetGeoConfigEnabled()
	configSources := m.config.Sources
	mode := m.status.Mode
	countries := m.status.AllowedCountries
	m.mu.RUnlock()

	result := Status{
		Enabled:          xdpEnabled == 1,
		Mode:             mode,
		AllowedCountries: countries,
		Sources:          make(map[SourceID]SourceStatus),
	}

	totalRules := 0
	var latestUpdate time.Time

	for id, src := range configSources {
		record, err := feed.GetLatestSourceStatus(m.db, feed.SourceTypeGeoBlocking, string(id))
		if err != nil || record == nil {
			result.Sources[SourceID(id)] = SourceStatus{Enabled: src.Enabled}
			continue
		}

		ss := SourceStatus{
			Enabled:    src.Enabled,
			LastUpdate: record.UpdatedAt,
			Success:    record.Status == "success",
			RuleCount:  record.RuleCount,
			Error:      record.ErrorMessage,
		}
		result.Sources[SourceID(id)] = ss

		if record.Status == "success" && record.RuleCount > 0 {
			totalRules += record.RuleCount
			if record.UpdatedAt.After(latestUpdate) {
				latestUpdate = record.UpdatedAt
			}
		}
	}

	result.TotalRules = totalRules
	if !latestUpdate.IsZero() {
		result.LastUpdate = latestUpdate
	}

	return &result
}

// TriggerUpdate 手动触发 GeoIP 更新
func (m *Manager) TriggerUpdate() error {
	logger.Info("[GeoBlocking] Manual update triggered")
	m.updateAllSources()
	return nil
}

// UpdateConfig 更新 GeoIP 配置（扩展支持 enabled 切换）
func (m *Manager) UpdateConfig(enabled bool, mode string, countries []string) error {
	wasEnabled := m.config.Enabled

	m.mu.Lock()
	m.config.Enabled = enabled
	m.status.Enabled = enabled
	m.status.Mode = mode
	m.status.AllowedCountries = countries
	m.config.Mode = mode
	m.config.AllowedCountries = countries
	m.mu.Unlock()

	// 更新内核配置总开关（enabled/mode）
	if err := m.updateKernelConfig(); err != nil {
		return err
	}

	switch {
	case enabled && !wasEnabled:
		// 从禁用→启用：立即拉取数据并同步到 eBPF map
		go func() {
			logger.Info("[GeoBlocking] Immediate fetch triggered by config enable")
			m.updateAllSources()
			if err := m.saveCache(); err != nil {
				logger.Errorf("[GeoBlocking] Failed to save cache after immediate fetch: %v", err)
			}
		}()
	case !enabled && wasEnabled:
		// 从启用→禁用：立即清理所有 GeoIP 规则并从 eBPF map 中移除
		go func() {
			logger.Info("[GeoBlocking] Immediate cleanup triggered by config disable")
			if err := m.syncer.RemoveAll(); err != nil {
				logger.Errorf("[GeoBlocking] Cleanup failed: %v", err)
			} else {
				logger.Info("[GeoBlocking] Cleanup completed, all GeoIP rules removed from eBPF")
			}
			if err := m.saveCache(); err != nil {
				logger.Errorf("[GeoBlocking] Failed to save cache after cleanup: %v", err)
			}
		}()
	}

	return nil
}

// GetConfig 获取当前 GeoBlocking 配置（返回可动态化的字段）
func (m *Manager) GetConfig() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sources := make(map[string]interface{})
	for id, src := range m.config.Sources {
		sources[id] = map[string]interface{}{
			"enabled":  src.Enabled,
			"periodic": src.Periodic,
			"schedule": src.Schedule,
			"url":      src.URL,
			"format":   src.Format,
		}
	}

	return map[string]interface{}{
		"enabled":           m.config.Enabled,
		"mode":              m.config.Mode,
		"allowed_countries": m.config.AllowedCountries,
		"sources":           sources,
	}
}

// UpdateSourceConfig 热更新 GeoIP 源配置（单个源的 enabled/periodic/schedule/url）
func (m *Manager) UpdateSourceConfig(sourceID string, enabled bool, periodic bool, schedule string, url string) error {
	m.mu.Lock()
	src, exists := m.config.Sources[sourceID]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("geo source %s not found", sourceID)
	}

	src.Enabled = enabled
	src.Periodic = periodic
	if schedule != "" {
		src.Schedule = schedule
	}
	if url != "" {
		src.URL = url
	}
	m.config.Sources[sourceID] = src

	// 如果模块已启动，需要重新调度 Cron 任务
	if m.cron != nil {
		// 移除旧的 Cron 任务
		if oldJobID, ok := m.jobIDs[SourceID(sourceID)]; ok {
			m.cron.Remove(oldJobID)
			delete(m.jobIDs, SourceID(sourceID))
		}

		// 如果启用且需要周期调度，注册新的 Cron 任务
		if enabled && periodic {
			if err := m.scheduleSource(SourceID(sourceID), src); err != nil {
				logger.Warnf("[GeoBlocking] Failed to reschedule %s: %v", sourceID, err)
			} else {
				logger.Infof("[GeoBlocking] [%s] Source config updated and rescheduled", sourceID)
			}
		} else if enabled && !periodic {
			logger.Infof("[GeoBlocking] [%s] Source enabled but periodic update disabled", sourceID)
		}
	}
	m.mu.Unlock()

	logger.Infof("[GeoBlocking] [%s] Source config updated: enabled=%v, periodic=%v, schedule=%s, url=%s",
		sourceID, enabled, periodic, schedule, url)

	// 启用时立即拉取一次数据
	go func() {
		m.mu.RLock()
		srcCfg := m.config.Sources[sourceID]
		m.mu.RUnlock()
		if err := m.updateSource(SourceID(sourceID), srcCfg); err != nil {
			logger.Errorf("[GeoBlocking] [%s] Immediate fetch after config change failed: %v", sourceID, err)
		}
		if err := m.saveCache(); err != nil {
			logger.Errorf("[GeoBlocking] Failed to save cache after source config update: %v", err)
		}
	}()

	return nil
}

// Stop 停止 GeoIP 管理器（幂等，多次调用安全）
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		logger.Info("[GeoBlocking] Stopping geo-blocking manager...")
		if m.cron != nil {
			m.cron.Stop()
		}
		close(m.done)
		logger.Info("[GeoBlocking] Stopped")
	})
}
