// Package threatintel 威胁情报模块
package threatintel

import (
	"fmt"
	"os"
	"path/filepath"
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
	config     *config.IntelConfig       // 威胁情报配置
	xdp        *ebpfs.Xdp                // XDP eBPF 程序接口
	fetcher    *feed.Fetcher           // 数据获取器（公共）
	parser     *Parser                   // 数据解析器
	rawFileDir string                    // 原始文件持久化目录
	syncer     *Syncer                   // 内核同步器
	cron       *cron.Cron                // Cron 调度器
	jobIDs     map[SourceID]cron.EntryID // 各源的 Cron 任务 ID
	done       chan struct{}             // 停止信号
	stopOnce   sync.Once               // 确保 Stop 只执行一次
	mu         sync.RWMutex              // 读写锁

	// 状态管理
	status       *Status                    // 模块状态
	lastUpdate   time.Time                  // 最后更新时间
	sourceStatus map[SourceID]*SourceStatus // 各情报源状态

	// 数据库支持和并发控制（使用公共组件）
	db            *gorm.DB                          // 数据库连接
	sourceMutexes *feed.MutexPool[SourceID]       // 互斥锁池（公共）
}

// NewManager 创建新的威胁情报管理器
func NewManager(cfg *config.IntelConfig, xdp *ebpfs.Xdp, db *gorm.DB) *Manager {
	return &Manager{
		config:        cfg,
		xdp:           xdp,
		fetcher:       feed.NewFetcher(30 * time.Second),
		parser:        NewParser(),
		rawFileDir:    cfg.PersistenceDir,
		syncer:        NewSyncer(xdp, cfg.BatchSize),
		done:          make(chan struct{}),
		sourceStatus:  make(map[SourceID]*SourceStatus),
		db:            db,
		sourceMutexes: feed.NewMutexPool[SourceID](),
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

	// 1. 从本地原始文件加载（离线启动支持）
	if err := m.loadFromRawFiles(); err != nil {
		logger.Warnf("[ThreatIntel] Failed to load raw files: %v", err)
	} else {
		logger.Info("[ThreatIntel] Loaded raw files successfully")
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

	// 5. 保存原始文件到本地
	if err := m.saveRawFile(sourceID, src.Format, data); err != nil {
		logger.Warnf("[ThreatIntel] [%s] Failed to save raw file: %v", sourceID, err)
	}

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

// loadFromRawFiles 从本地原始文件加载威胁情报（离线启动支持）
// 读取各源的原始文件，重新解析后加载到 eBPF map
func (m *Manager) loadFromRawFiles() error {
	loadedAny := false

	for id, src := range m.config.Sources {
		if !src.Enabled {
			continue
		}

		sourceID := SourceID(id)
		filePath := m.getRawFilePath(sourceID, src.Format)
		rawBytes, err := os.ReadFile(filePath)
		if err != nil {
			logger.Warnf("[ThreatIntel] [%s] Raw file not found (%s), skipping", sourceID, filePath)
			continue
		}

		logger.Infof("[ThreatIntel] [%s] Loading from raw file: %s (%d bytes)", sourceID, filePath, len(rawBytes))

		// 重新解析原始文件
		parsed, err := m.parser.Parse(rawBytes, src.Format, sourceID)
		if err != nil {
			logger.Warnf("[ThreatIntel] [%s] Failed to parse raw file: %v", sourceID, err)
			m.setSourceStatusInline(sourceID, false, 0, err.Error())
			continue
		}

		sourceMask := sourceIDToMask(sourceID)
		if err := m.syncer.LoadAll(parsed, sourceMask); err != nil {
			logger.Warnf("[ThreatIntel] [%s] Failed to load from raw file: %v", sourceID, err)
			m.setSourceStatusInline(sourceID, false, 0, err.Error())
			continue
		}

		m.setSourceStatusInline(sourceID, true, parsed.TotalCount(), "")
		loadedAny = true
	}

	if !loadedAny {
		return fmt.Errorf("no raw files found for enabled sources")
	}

	// 计算总规则数
	totalRules := 0
	for _, s := range m.sourceStatus {
		totalRules += s.RuleCount
	}
	m.status.TotalRules = totalRules
	m.status.LastUpdate = time.Now()

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

// getRawFilePath 返回指定源的原始文件路径
func (m *Manager) getRawFilePath(sourceID SourceID, format string) string {
	ext := sourceFileExt(format)
	return filepath.Join(m.rawFileDir, string(sourceID)+ext)
}

// saveRawFile 原子写入原始文件到本地磁盘
func (m *Manager) saveRawFile(sourceID SourceID, format string, data []byte) error {
	path := m.getRawFilePath(sourceID, format)
	tmpPath := path + ".tmp"

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create raw file dir failed: %w", err)
	}

	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write tmp file failed: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename raw file failed: %w", err)
	}

	logger.Infof("[ThreatIntel] [%s] Saved raw file: %s (%d bytes)", sourceID, path, len(data))
	return nil
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

// GetStatus 获取威胁情报模块状态（优先查 DB，DB 无记录返回空）
func (m *Manager) GetStatus() *Status {
	m.mu.RLock()
	enabled := m.config.Enabled
	configSources := m.config.Sources
	m.mu.RUnlock()

	result := Status{
		Enabled: enabled,
		Sources: make(map[SourceID]SourceStatus),
	}

	totalRules := 0
	var latestUpdate time.Time

	for id, src := range configSources {
		record, err := feed.GetLatestSourceStatus(m.db, feed.SourceTypeIntel, string(id))
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

// TriggerUpdate 手动触发威胁情报更新
func (m *Manager) TriggerUpdate() error {
	logger.Info("[ThreatIntel] Manual update triggered")
	m.updateAllSources()
	return nil
}

// UpdateSourceConfig 热更新情报源配置（单个源的 enabled/schedule/url）
func (m *Manager) UpdateSourceConfig(sourceID string, enabled bool, schedule string, url string) error {
	wasEnabled := false

	m.mu.Lock()
	src, exists := m.config.Sources[sourceID]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("source %s not found", sourceID)
	}

	wasEnabled = src.Enabled
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
	m.mu.Unlock()

	// 状态切换时的即时操作
	switch {
	case enabled && !wasEnabled:
		// 从禁用→启用：立即拉取一次数据并同步到 eBPF map
		go func() {
			logger.Infof("[ThreatIntel] [%s] Immediate fetch triggered by config change", sourceID)
			if err := m.updateSource(SourceID(sourceID), src); err != nil {
				logger.Errorf("[ThreatIntel] [%s] Immediate fetch failed: %v", sourceID, err)
				m.updateSourceStatus(SourceID(sourceID), false, 0, err.Error())
			} else {
				logger.Infof("[ThreatIntel] [%s] Immediate fetch completed, rules synced to eBPF", sourceID)
			}
		}()
	case !enabled && wasEnabled:
		// 从启用→禁用：立即清理该源的规则并从 eBPF map 中移除
		go func() {
			sourceMask := sourceIDToMask(SourceID(sourceID))
			logger.Infof("[ThreatIntel] [%s] Immediate cleanup triggered by config change (mask=0x%x)", sourceID, sourceMask)
			if err := m.syncer.RemoveBySourceMask(sourceMask); err != nil {
				logger.Errorf("[ThreatIntel] [%s] Cleanup failed: %v", sourceID, err)
			} else {
				logger.Infof("[ThreatIntel] [%s] Cleanup completed, rules removed from eBPF", sourceID)
			}
		}()
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

// Stop 停止威胁情报管理器（幂等，多次调用安全）
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		logger.Info("[ThreatIntel] Stopping threat intelligence manager...")
		if m.cron != nil {
			m.cron.Stop()
		}
		close(m.done)
		logger.Info("[ThreatIntel] Stopped")
	})
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
