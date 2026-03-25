// Package geoblocking 地域封禁模块
package geoblocking

import (
	"fmt"
	"sync"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
	"rho-aias/internal/models"

	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

// Manager GeoIP 管理器
// 负责协调 GeoIP 的获取、解析、同步和持久化
type Manager struct {
	config   *config.GeoBlockingConfig // GeoBlocking 配置
	xdp      *ebpfs.Xdp                // XDP eBPF 程序接口
	fetcher  *Fetcher                  // 数据获取器
	parser   *Parser                   // 数据解析器
	cache    *Cache                    // 持久化缓存
	syncer   *Syncer                   // 内核同步器
	cron     *cron.Cron                // Cron 调度器
	jobIDs   map[SourceID]cron.EntryID // 各源的 Cron 任务 ID
	done     chan struct{}             // 停止信号
	mu       sync.RWMutex              // 读写锁

	// 状态管理
	status       *Status                    // 模块状态
	sourceStatus map[SourceID]*SourceStatus // 各 GeoIP 源状态

	// 新增：数据库支持和并发控制
	db            *gorm.DB                 // 数据库连接
	sourceMutexes map[SourceID]*sync.Mutex // 各数据源的互斥锁
}

// NewManager 创建新的 GeoIP 管理器
// cfg: GeoBlocking 配置
// xdp: XDP eBPF 程序接口
// db: 数据库连接（用于记录状态）
func NewManager(cfg *config.GeoBlockingConfig, xdp *ebpfs.Xdp, db *gorm.DB) *Manager {
	return &Manager{
		config:       cfg,
		xdp:          xdp,
		fetcher:      NewFetcher(30 * time.Second),
		parser:       NewParser(),
		cache:        NewCache(cfg.PersistenceDir),
		syncer:       NewSyncer(xdp, cfg.BatchSize),
		done:         make(chan struct{}),
		sourceStatus: make(map[SourceID]*SourceStatus),
		db:           db,
		sourceMutexes: make(map[SourceID]*sync.Mutex),
		status: &Status{
			Enabled:          cfg.Enabled,
			Mode:             cfg.Mode,
			AllowedCountries: cfg.AllowedCountries,
			Sources:          make(map[SourceID]SourceStatus),
		},
	}
}

// Start 启动 GeoIP 管理器
// 1. 加载本地缓存（离线启动支持）
// 2. 为每个启用的源注册独立的 Cron 任务
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		logger.Info("[GeoBlocking] Geo-blocking module is disabled")
		return nil
	}

	logger.Info("[GeoBlocking] Starting geo-blocking manager...")

	// 初始状态：不启用 geo_config（等待数据加载）
	// LoadAll 或 SyncToKernel 会在数据加载成功后自动启用

	// 1. 加载本地缓存（离线启动）
	if err := m.loadFromCache(); err != nil {
		logger.Warnf("[GeoBlocking] Failed to load cache: %v", err)
		// 缓存加载失败是正常的（首次运行），不需要特殊处理
	} else {
		logger.Info("[GeoBlocking] Loaded cache successfully")
	}

	// 2. 创建 Cron 调度器
	m.cron = cron.New()
	m.jobIDs = make(map[SourceID]cron.EntryID)

	// 3. 为每个启用的源注册独立的 Cron 任务
	for sourceID, source := range m.config.Sources {
		if source.Enabled && source.Periodic {
			sid := SourceID(sourceID)
			if err := m.scheduleSource(sid, source); err != nil {
				logger.Warnf("[GeoBlocking] Failed to schedule %s: %v", sourceID, err)
				// 继续尝试其他源，不中断启动
			}
		} else if source.Enabled && !source.Periodic {
			logger.Infof("[GeoBlocking] [%s] Periodic update disabled, skipping cron schedule", sourceID)
		}
	}

	// 4. 启动 Cron 调度器
	m.cron.Start()

	logger.Info("[GeoBlocking] Started successfully")
	return nil
}

// updateKernelConfig 更新内核配置
func (m *Manager) updateKernelConfig() error {
	mode := uint32(0) // default: whitelist
	if m.status.Mode == "blacklist" {
		mode = 1
	}

	return m.xdp.UpdateGeoConfig(m.config.Enabled, mode)
}

// scheduleSource 为单个源注册 Cron 任务
func (m *Manager) scheduleSource(sourceID SourceID, source config.GeoIPSource) error {
	// 解析 Cron 表达式
	schedule, err := cron.ParseStandard(source.Schedule)
	if err != nil {
		return fmt.Errorf("invalid cron schedule '%s' for %s: %w", source.Schedule, sourceID, err)
	}

	// 创建 Cron 任务
	jobID := m.cron.Schedule(schedule, cron.FuncJob(func() {
		logger.Infof("[GeoBlocking] [%s] Scheduled update triggered", sourceID)
		if err := m.updateSource(sourceID, source); err != nil {
			logger.Errorf("[GeoBlocking] [%s] update failed: %v", sourceID, err)
			m.updateSourceStatus(sourceID, false, 0, err.Error())
		}
		// 更新后保存缓存
		if err := m.saveCache(); err != nil {
			logger.Errorf("[GeoBlocking] Failed to save cache: %v", err)
		}
	}))

	m.jobIDs[sourceID] = jobID

	// 初始化源状态
	status, exists := m.sourceStatus[sourceID]
	if !exists {
		status = &SourceStatus{}
		m.sourceStatus[sourceID] = status
	}
	status.Enabled = true
	m.status.Sources[sourceID] = *status

	logger.Infof("[GeoBlocking] [%s] Scheduled with cron: %s", sourceID, source.Schedule)
	return nil
}

// updateAllSources 更新所有启用的 GeoIP 源（用于手动触发）
func (m *Manager) updateAllSources() {
	logger.Info("[GeoBlocking] Starting update for all sources...")

	// 获取所有启用的 GeoIP 源
	sources := m.getEnabledSources()
	if len(sources) == 0 {
		logger.Info("[GeoBlocking] No enabled sources")
		return
	}

	// 更新每个 GeoIP 源
	for sourceID, source := range sources {
		if err := m.updateSource(sourceID, source); err != nil {
			logger.Errorf("[GeoBlocking] [%s] update failed: %v", sourceID, err)
			m.updateSourceStatus(sourceID, false, 0, err.Error())
		}
	}

	// 更新后保存缓存
	if err := m.saveCache(); err != nil {
		logger.Errorf("[GeoBlocking] Failed to save cache: %v", err)
	}

	logger.Info("[GeoBlocking] Update completed")
}

// updateSource 更新单个 GeoIP 源
// sourceID: GeoIP 源标识符
// source: GeoIP 源配置
func (m *Manager) updateSource(sourceID SourceID, source config.GeoIPSource) error {
	// 检查互斥锁，如果正在执行则跳过
	mu := m.getSourceMutex(sourceID)
	if !mu.TryLock() {
		logger.Warnf("[GeoBlocking] [%s] Update skipped - already in progress", sourceID)
		return fmt.Errorf("update already in progress")
	}
	defer mu.Unlock()

	logger.Infof("[GeoBlocking] [%s] Fetching from %s", sourceID, source.URL)
	startTime := time.Now()

	// 1. 获取数据
	data, err := m.fetcher.Fetch(source.URL)
	if err != nil {
		// 记录失败状态到数据库
		duration := time.Since(startTime).Milliseconds()
		_ = m.recordStatusToDB(string(sourceID), string(sourceID), "failed", 0, err.Error(), duration)
		return err
	}
	logger.Infof("[GeoBlocking] [%s] Fetched %d bytes", sourceID, len(data))

	// 2. 解析数据（传递允许的国家列表）
	parsed, err := m.parser.Parse(data, source.Format, m.config.AllowedCountries, sourceID)
	if err != nil {
		// 记录失败状态到数据库
		duration := time.Since(startTime).Milliseconds()
		_ = m.recordStatusToDB(string(sourceID), string(sourceID), "failed", 0, err.Error(), duration)
		return err
	}
	logger.Infof("[GeoBlocking] [%s] Parsed %d rules", sourceID, parsed.TotalCount())

	// 3. 同步到内核
	geoConfig := &GeoConfig{
		Enabled:              m.config.Enabled,
		Mode:                  m.config.Mode,
		AllowedCountries:      m.config.AllowedCountries,
		AllowPrivateNetworks: m.config.AllowPrivateNetworks,
	}
	if err := m.syncer.SyncToKernel(parsed, geoConfig); err != nil {
		// 记录失败状态到数据库
		duration := time.Since(startTime).Milliseconds()
		_ = m.recordStatusToDB(string(sourceID), string(sourceID), "failed", 0, err.Error(), duration)
		return err
	}

	// 4. 更新状态
	m.updateSourceStatus(sourceID, true, parsed.TotalCount(), "")

	// 5. 记录成功状态到数据库
	duration := time.Since(startTime).Milliseconds()
	if err := m.recordStatusToDB(string(sourceID), string(sourceID), "success", parsed.TotalCount(), "", duration); err != nil {
		logger.Errorf("[GeoBlocking] [%s] Failed to record status to DB: %v", sourceID, err)
	}

	// 6. 清理 30 天前的历史记录
	if err := m.cleanOldRecords(string(sourceID)); err != nil {
		logger.Errorf("[GeoBlocking] [%s] Failed to clean old records: %v", sourceID, err)
	}

	return nil
}

// loadFromCache 从本地缓存加载 GeoIP（离线启动支持）
// 注意：此函数在 Start() 的 m.mu 锁保护下调用，不能再次获取 m.mu
func (m *Manager) loadFromCache() error {
	if !m.cache.Exists() {
		return ErrGeoIPCacheNotFound
	}

	cacheData, err := m.cache.Load()
	if err != nil {
		return err
	}

	logger.Infof("[GeoBlocking] Loading cache with %d sources...", len(cacheData.Sources))

	// 在 Start() 的 m.mu 锁保护下，直接更新状态（避免重复获取锁）
	now := time.Now()

	// 加载每个源的数据
	for sourceID, data := range cacheData.Sources {
		logger.Infof("[GeoBlocking] [%s] Loading %d rules from cache", sourceID, data.TotalCount())

		geoConfig := &GeoConfig{
			Enabled:              cacheData.Config.Enabled,
			Mode:                  cacheData.Config.Mode,
			AllowedCountries:      cacheData.Config.AllowedCountries,
			AllowPrivateNetworks: m.config.AllowPrivateNetworks, // 从当前配置读取
		}
		if err := m.syncer.LoadAll(&data, geoConfig); err != nil {
			logger.Warnf("[GeoBlocking] [%s] Failed to load from cache: %v", sourceID, err)
			// 失败状态
			status, exists := m.sourceStatus[sourceID]
			if !exists {
				status = &SourceStatus{}
				m.sourceStatus[sourceID] = status
			}
			status.Enabled = true
			status.LastUpdate = now
			status.Success = false
			status.RuleCount = 0
			status.Error = err.Error()
			m.status.Sources[sourceID] = *status
			continue
		}

		// 成功状态 - 直接更新，避免调用 updateSourceStatus() 导致死锁
		status, exists := m.sourceStatus[sourceID]
		if !exists {
			status = &SourceStatus{}
			m.sourceStatus[sourceID] = status
		}
		status.Enabled = true
		status.LastUpdate = now
		status.Success = true
		status.RuleCount = data.TotalCount()
		status.Error = ""
		m.status.Sources[sourceID] = *status
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

// saveCache 保存 GeoIP 到本地缓存
func (m *Manager) saveCache() error {
	cacheData := NewCacheData()
	cacheData.Config = GeoConfig{
		Enabled:          m.config.Enabled,
		Mode:             m.config.Mode,
		AllowedCountries: m.config.AllowedCountries,
		// 不保存 AllowPrivateNetworks 到缓存（始终从配置文件读取）
	}

	m.mu.RLock()
	for sourceID, status := range m.sourceStatus {
		if status.Success && status.RuleCount > 0 {
			// 从内核获取当前规则构建缓存数据
			rules, _ := m.xdp.GetGeoIPRules()
			data := NewGeoIPData(sourceID)

			for _, r := range rules {
				data.AddCIDR(r)
			}
			cacheData.Sources[sourceID] = *data
		}
	}
	m.mu.RUnlock()

	return m.cache.Save(cacheData)
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

	for sourceID, source := range m.config.Sources {
		if source.Enabled {
			sources[SourceID(sourceID)] = source
		}
	}

	return sources
}

// GetStatus 获取 GeoIP 模块状态
func (m *Manager) GetStatus() *Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 从 eBPF 读取实际的 enabled 状态
	enabled := m.xdp.GetGeoConfigEnabled()

	// 返回副本
	statusCopy := *m.status
	statusCopy.Enabled = (enabled == 1) // 反映实际状态
	statusCopy.Sources = make(map[SourceID]SourceStatus)
	for k, v := range m.status.Sources {
		statusCopy.Sources[k] = v
	}

	return &statusCopy
}

// TriggerUpdate 手动触发 GeoIP 更新
func (m *Manager) TriggerUpdate() error {
	logger.Info("[GeoBlocking] Manual update triggered")
	m.updateAllSources()
	return nil
}

// UpdateConfig 更新 GeoIP 配置
func (m *Manager) UpdateConfig(mode string, countries []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.status.Mode = mode
	m.status.AllowedCountries = countries
	m.config.Mode = mode
	m.config.AllowedCountries = countries

	// 更新内核配置
	if err := m.updateKernelConfig(); err != nil {
		return err
	}

	// 触发更新以应用新配置
	go m.updateAllSources()

	return nil
}

// Stop 停止 GeoIP 管理器
func (m *Manager) Stop() {
	logger.Info("[GeoBlocking] Stopping geo-blocking manager...")
	if m.cron != nil {
		m.cron.Stop() // 停止所有 Cron 任务
	}
	close(m.done)
	logger.Info("[GeoBlocking] Stopped")
}

// getSourceMutex 获取指定数据源的互斥锁
func (m *Manager) getSourceMutex(sourceID SourceID) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()

	mu, exists := m.sourceMutexes[sourceID]
	if !exists {
		mu = &sync.Mutex{}
		m.sourceMutexes[sourceID] = mu
	}
	return mu
}

// recordStatusToDB 记录状态到数据库
func (m *Manager) recordStatusToDB(sourceID, sourceName, status string, ruleCount int, errMsg string, duration int64) error {
	if m.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	record := &models.SourceStatusRecord{
		SourceType:   "geo_blocking",
		SourceID:     sourceID,
		SourceName:   sourceName,
		Status:       status,
		RuleCount:    ruleCount,
		ErrorMessage: errMsg,
		Duration:     int(duration),
		UpdatedAt:    time.Now(),
		CreatedAt:    time.Now(),
	}

	if err := m.db.Create(record).Error; err != nil {
		return fmt.Errorf("failed to create status record: %w", err)
	}

	return nil
}

// cleanOldRecords 清理 30 天前的历史记录
func (m *Manager) cleanOldRecords(sourceID string) error {
	if m.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	return models.CleanOldRecords(m.db, "geo_blocking", sourceID)
}
