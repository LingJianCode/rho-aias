// Package threatintel 威胁情报模块
package threatintel

import (
	"fmt"
	"sync"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"
	"rho-aias/internal/feed"

	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

// Manager 威胁情报管理器
// 负责协调威胁情报的获取、解析、同步和持久化
type Manager struct {
	config  *config.IntelConfig       // 威胁情报配置
	xdp     *ebpfs.Xdp                // XDP eBPF 程序接口
	fetcher *feed.Fetcher           // 数据获取器（公共）
	parser  *Parser                   // 数据解析器
	cache   *feed.Cache[CacheData]  // 持久化缓存（公共泛型）
	syncer  *Syncer                   // 内核同步器
	cron    *cron.Cron                // Cron 调度器
	jobIDs  map[SourceID]cron.EntryID // 各源的 Cron 任务 ID
	done    chan struct{}             // 停止信号
	mu      sync.RWMutex              // 读写锁

	// 状态管理
	status       *Status                    // 模块状态
	lastUpdate   time.Time                  // 最后更新时间
	sourceStatus map[SourceID]*SourceStatus // 各情报源状态

	// 数据库支持和并发控制（使用公共组件）
	db            *gorm.DB                          // 数据库连接
	sourceMutexes *feed.MutexPool[SourceID]       // 互斥锁池（公共）

	// 每个源的最新规则数据（用于 saveCache 按源分类保存）
	sourceRules map[SourceID]*IntelData
}

// NewManager 创建新的威胁情报管理器
func NewManager(cfg *config.IntelConfig, xdp *ebpfs.Xdp, db *gorm.DB) *Manager {
	return &Manager{
		config:        cfg,
		xdp:           xdp,
		fetcher:       feed.NewFetcher(30 * time.Second),
		parser:        NewParser(),
		cache:         feed.NewCache[CacheData](cfg.PersistenceDir, "intel_cache.bin"),
		syncer:        NewSyncer(xdp, cfg.BatchSize),
		done:          make(chan struct{}),
		sourceStatus:  make(map[SourceID]*SourceStatus),
		db:            db,
		sourceMutexes: feed.NewMutexPool[SourceID](),
		sourceRules:   make(map[SourceID]*IntelData),
		status: &Status{
			Enabled: cfg.Enabled,
			Sources: make(map[SourceID]SourceStatus),
		},
	}
}

// Start 启动威胁情报管理器
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		logger.Info("[ThreatIntel] Threat intelligence module is disabled")
		return nil
	}

	logger.Info("[ThreatIntel] Starting threat intelligence manager...")

	// 1. 加载本地缓存（离线启动）
	if err := m.loadFromCache(); err != nil {
		logger.Warnf("[ThreatIntel] Failed to load cache: %v", err)
	} else {
		logger.Info("[ThreatIntel] Loaded cache successfully")
	}

	// 2. 创建 Cron 调度器
	m.cron = cron.New()
	m.jobIDs = make(map[SourceID]cron.EntryID)

	// 3. 为每个启用的源注册独立的 Cron 任务
	for id, src := range m.config.Sources {
		if src.Enabled && src.Periodic {
			if err := m.scheduleSource(SourceID(id), src); err != nil {
				logger.Warnf("[ThreatIntel] Failed to schedule %s: %v", id, err)
			}
		} else if src.Enabled && !src.Periodic {
			logger.Infof("[ThreatIntel] [%s] Periodic update disabled, skipping cron schedule", id)
		}
	}

	// 4. 启动 Cron 调度器
	m.cron.Start()

	logger.Info("[ThreatIntel] Started successfully")
	return nil
}

// scheduleSource 为单个源注册 Cron 任务
func (m *Manager) scheduleSource(sourceID SourceID, src config.IntelSource) error {
	schedule, err := cron.ParseStandard(src.Schedule)
	if err != nil {
		return fmt.Errorf("invalid cron schedule '%s' for %s: %w", src.Schedule, sourceID, err)
	}

	jobID := m.cron.Schedule(schedule, cron.FuncJob(func() {
		logger.Infof("[ThreatIntel] [%s] Scheduled update triggered", sourceID)
		if err := m.updateSource(sourceID, src); err != nil {
			logger.Errorf("[ThreatIntel] [%s] update failed: %v", sourceID, err)
			m.updateSourceStatus(sourceID, false, 0, err.Error())
		}
		if err := m.saveCache(); err != nil {
			logger.Errorf("[ThreatIntel] Failed to save cache: %v", err)
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

	logger.Infof("[ThreatIntel] [%s] Scheduled with cron: %s", sourceID, src.Schedule)
	return nil
}

// updateAllSources 更新所有启用的威胁情报源（用于手动触发）
func (m *Manager) updateAllSources() {
	logger.Info("[ThreatIntel] Starting update for all sources...")

	sources := m.getEnabledSources()
	if len(sources) == 0 {
		logger.Info("[ThreatIntel] No enabled sources")
		return
	}

	for sourceID, src := range sources {
		if err := m.updateSource(sourceID, src); err != nil {
			logger.Errorf("[ThreatIntel] [%s] update failed: %v", sourceID, err)
			m.updateSourceStatus(sourceID, false, 0, err.Error())
		}
	}

	if err := m.saveCache(); err != nil {
		logger.Errorf("[ThreatIntel] Failed to save cache: %v", err)
	}

	logger.Info("[ThreatIntel] Update completed")
}

// updateSource 更新单个威胁情报源
func (m *Manager) updateSource(sourceID SourceID, src config.IntelSource) error {
	mu := m.sourceMutexes.Get(sourceID)
	if !mu.TryLock() {
		logger.Warnf("[ThreatIntel] [%s] Update skipped - already in progress", sourceID)
		return fmt.Errorf("update already in progress")
	}
	defer mu.Unlock()

	logger.Infof("[ThreatIntel] [%s] Fetching from %s", sourceID, src.URL)
	startTime := time.Now()

	// 1. 获取数据
	data, err := m.fetcher.Fetch(src.URL)
	if err != nil {
		duration := time.Since(startTime).Milliseconds()
		_ = feed.RecordStatus(m.db, feed.SourceTypeIntel, string(sourceID), string(sourceID), "failed", 0, err.Error(), duration)
		return err
	}
	logger.Infof("[ThreatIntel] [%s] Fetched %d bytes", sourceID, len(data))

	// 2. 解析数据
	parsed, err := m.parser.Parse(data, src.Format, sourceID)
	if err != nil {
		duration := time.Since(startTime).Milliseconds()
		_ = feed.RecordStatus(m.db, feed.SourceTypeIntel, string(sourceID), string(sourceID), "failed", 0, err.Error(), duration)
		return err
	}
	logger.Infof("[ThreatIntel] [%s] Parsed %d rules (exact: %d, cidr: %d)",
		sourceID, parsed.TotalCount(), len(parsed.IPv4Exact), len(parsed.IPv4CIDR))

	// 3. 同步到内核（传递来源掩码）
	sourceMask := sourceIDToMask(sourceID)
	if err := m.syncer.SyncToKernel(parsed, sourceMask); err != nil {
		duration := time.Since(startTime).Milliseconds()
		_ = feed.RecordStatus(m.db, feed.SourceTypeIntel, string(sourceID), string(sourceID), "failed", 0, err.Error(), duration)
		return err
	}

	// 4. 更新状态
	m.updateSourceStatus(sourceID, true, parsed.TotalCount(), "")

	// 5. 保存该源的规则数据
	m.mu.Lock()
	m.sourceRules[sourceID] = parsed
	m.mu.Unlock()

	// 6. 记录成功状态 + 清理旧记录
	duration := time.Since(startTime).Milliseconds()
	if err := feed.RecordStatus(m.db, feed.SourceTypeIntel, string(sourceID), string(sourceID), "success", parsed.TotalCount(), "", duration); err != nil {
		logger.Errorf("[ThreatIntel] [%s] Failed to record status to DB: %v", sourceID, err)
	}
	if err := feed.CleanOldRecords(m.db, feed.SourceTypeIntel, string(sourceID)); err != nil {
		logger.Errorf("[ThreatIntel] [%s] Failed to clean old records: %v", sourceID, err)
	}

	return nil
}

// loadFromCache 从本地缓存加载威胁情报（离线启动支持）
func (m *Manager) loadFromCache() error {
	if !m.cache.Exists() {
		return ErrThreatIntelCacheNotFound
	}

	cacheData, err := m.cache.Load()
	if err != nil {
		return err
	}

	logger.Infof("[ThreatIntel] Loading cache with %d sources...", len(cacheData.Sources))

	now := time.Now()
	m.lastUpdate = time.Unix(cacheData.Timestamp, 0)

	for sourceID, data := range cacheData.Sources {
		logger.Infof("[ThreatIntel] [%s] Loading %d rules from cache", sourceID, data.TotalCount())

		sourceMask := sourceIDToMask(sourceID)
		if err := m.syncer.LoadAll(&data, sourceMask); err != nil {
			logger.Warnf("[ThreatIntel] [%s] Failed to load from cache: %v", sourceID, err)
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

// setSourceStatusInline 内联更新源状态（避免在已持锁场景下调用 updateSourceStatus 导致死锁）
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

// saveCache 保存威胁情报到本地缓存
func (m *Manager) saveCache() error {
	cacheData := NewCacheData()

	m.mu.RLock()
	for sourceID, status := range m.sourceStatus {
		if status.Success && status.RuleCount > 0 {
			data := NewIntelData(sourceID)

			if sourceRules, ok := m.sourceRules[sourceID]; ok {
				for _, ip := range sourceRules.IPv4Exact {
					data.AddIPv4(ip)
				}
				for _, cidr := range sourceRules.IPv4CIDR {
					data.AddCIDR(cidr)
				}
			}

			cacheData.Sources[sourceID] = *data
		}
	}
	m.mu.RUnlock()

	return m.cache.Save(*cacheData)
}

// updateSourceStatus 更新威胁情报源状态
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

	m.lastUpdate = now

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

// getEnabledSources 获取所有启用的威胁情报源配置
func (m *Manager) getEnabledSources() map[SourceID]config.IntelSource {
	sources := make(map[SourceID]config.IntelSource)

	for sourceID, src := range m.config.Sources {
		if src.Enabled {
			sources[SourceID(sourceID)] = src
		}
	}

	return sources
}

// GetStatus 获取威胁情报模块状态
func (m *Manager) GetStatus() *Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	statusCopy := *m.status
	statusCopy.Sources = make(map[SourceID]SourceStatus)
	for k, v := range m.status.Sources {
		statusCopy.Sources[k] = v
	}

	return &statusCopy
}

// TriggerUpdate 手动触发威胁情报更新
func (m *Manager) TriggerUpdate() error {
	logger.Info("[ThreatIntel] Manual update triggered")
	m.updateAllSources()
	return nil
}

// UpdateSourceConfig 热更新情报源配置（单个源的 enabled/schedule/url）
func (m *Manager) UpdateSourceConfig(sourceID string, enabled bool, schedule string, url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	src, exists := m.config.Sources[sourceID]
	if !exists {
		return fmt.Errorf("source %s not found", sourceID)
	}

	src.Enabled = enabled
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
		if enabled && src.Periodic {
			if err := m.scheduleSource(SourceID(sourceID), src); err != nil {
				logger.Warnf("[ThreatIntel] Failed to reschedule %s: %v", sourceID, err)
			}
		}
	}

	logger.Infof("[ThreatIntel] Source config updated: %s, enabled=%v, schedule=%s", sourceID, enabled, schedule)
	return nil
}

// UpdateConfig 热更新情报模块总开关
func (m *Manager) UpdateConfig(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.Enabled = enabled
	m.status.Enabled = enabled
	logger.Infof("[ThreatIntel] Config updated: enabled=%v", enabled)
}

// GetConfig 获取当前情报模块配置（返回可动态化的字段）
func (m *Manager) GetConfig() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sources := make(map[string]interface{})
	for id, src := range m.config.Sources {
		sources[id] = map[string]interface{}{
			"enabled":  src.Enabled,
			"schedule": src.Schedule,
			"url":      src.URL,
			"format":   src.Format,
		}
	}

	return map[string]interface{}{
		"enabled": m.config.Enabled,
		"sources": sources,
	}
}

// Stop 停止威胁情报管理器
func (m *Manager) Stop() {
	logger.Info("[ThreatIntel] Stopping threat intelligence manager...")
	if m.cron != nil {
		m.cron.Stop()
	}
	close(m.done)
	logger.Info("[ThreatIntel] Stopped")
}

// sourceIDToMask 将 SourceID 转换为来源掩码
func sourceIDToMask(sourceID SourceID) uint32 {
	switch sourceID {
	case SourceIpsum:
		return 0x01
	case SourceSpamhaus:
		return 0x02
	case SourceManual:
		return 0x04
	case SourceWAF:
		return 0x08
	case SourceDDoS:
		return 0x10
	default:
		return 0
	}
}
