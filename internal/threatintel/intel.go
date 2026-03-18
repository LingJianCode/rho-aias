// Package threatintel 威胁情报模块
package threatintel

import (
	"fmt"
	"sync"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/logger"

	"github.com/robfig/cron/v3"
)

// Manager 威胁情报管理器
// 负责协调威胁情报的获取、解析、同步和持久化
type Manager struct {
	config  *config.IntelConfig       // 威胁情报配置
	xdp     *ebpfs.Xdp                // XDP eBPF 程序接口
	fetcher *Fetcher                  // 数据获取器
	parser  *Parser                   // 数据解析器
	cache   *Cache                    // 持久化缓存
	syncer  *Syncer                   // 内核同步器
	cron    *cron.Cron                // Cron 调度器
	jobIDs  map[SourceID]cron.EntryID // 各源的 Cron 任务 ID
	done    chan struct{}             // 停止信号
	mu      sync.RWMutex              // 读写锁

	// 状态管理
	status       *Status                    // 模块状态
	lastUpdate   time.Time                  // 最后更新时间
	sourceStatus map[SourceID]*SourceStatus // 各情报源状态
}

// NewManager 创建新的威胁情报管理器
// cfg: 威胁情报配置
// xdp: XDP eBPF 程序接口
func NewManager(cfg *config.IntelConfig, xdp *ebpfs.Xdp) *Manager {
	return &Manager{
		config:       cfg,
		xdp:          xdp,
		fetcher:      NewFetcher(30 * time.Second),
		parser:       NewParser(),
		cache:        NewCache(cfg.PersistenceDir),
		syncer:       NewSyncer(xdp, cfg.BatchSize),
		done:         make(chan struct{}),
		sourceStatus: make(map[SourceID]*SourceStatus),
		status: &Status{
			Enabled: cfg.Enabled,
			Sources: make(map[SourceID]SourceStatus),
		},
	}
}

// Start 启动威胁情报管理器
// 1. 加载本地缓存（离线启动支持）
// 2. 为每个启用的源注册独立的 Cron 任务
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
	for sourceID, source := range m.config.Sources {
		if source.Enabled {
			sid := SourceID(sourceID)
			if err := m.scheduleSource(sid, source); err != nil {
				logger.Warnf("[ThreatIntel] Failed to schedule %s: %v", sourceID, err)
				// 继续尝试其他源，不中断启动
			}
		}
	}

	// 4. 启动 Cron 调度器
	m.cron.Start()

	logger.Info("[ThreatIntel] Started successfully")
	return nil
}

// scheduleSource 为单个源注册 Cron 任务
func (m *Manager) scheduleSource(sourceID SourceID, source config.IntelSource) error {
	// 解析 Cron 表达式
	schedule, err := cron.ParseStandard(source.Schedule)
	if err != nil {
		return fmt.Errorf("invalid cron schedule '%s' for %s: %w", source.Schedule, sourceID, err)
	}

	// 创建 Cron 任务
	jobID := m.cron.Schedule(schedule, cron.FuncJob(func() {
		logger.Infof("[ThreatIntel] [%s] Scheduled update triggered", sourceID)
		if err := m.updateSource(sourceID, source); err != nil {
			logger.Errorf("[ThreatIntel] [%s] update failed: %v", sourceID, err)
			m.updateSourceStatus(sourceID, false, 0, err.Error())
		}
		// 更新后保存缓存
		if err := m.saveCache(); err != nil {
			logger.Errorf("[ThreatIntel] Failed to save cache: %v", err)
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

	logger.Infof("[ThreatIntel] [%s] Scheduled with cron: %s", sourceID, source.Schedule)
	return nil
}

// updateAllSources 更新所有启用的威胁情报源（用于手动触发）
func (m *Manager) updateAllSources() {
	logger.Info("[ThreatIntel] Starting update for all sources...")

	// 获取所有启用的情报源
	sources := m.getEnabledSources()
	if len(sources) == 0 {
		logger.Info("[ThreatIntel] No enabled sources")
		return
	}

	// 更新每个情报源
	for sourceID, source := range sources {
		if err := m.updateSource(sourceID, source); err != nil {
			logger.Errorf("[ThreatIntel] [%s] update failed: %v", sourceID, err)
			m.updateSourceStatus(sourceID, false, 0, err.Error())
		}
	}

	// 更新后保存缓存
	if err := m.saveCache(); err != nil {
		logger.Errorf("[ThreatIntel] Failed to save cache: %v", err)
	}

	logger.Info("[ThreatIntel] Update completed")
}

// updateSource 更新单个威胁情报源
// sourceID: 情报源标识符
// source: 情报源配置
func (m *Manager) updateSource(sourceID SourceID, source config.IntelSource) error {
	logger.Infof("[ThreatIntel] [%s] Fetching from %s", sourceID, source.URL)

	// 1. 获取数据
	data, err := m.fetcher.Fetch(source.URL)
	if err != nil {
		return err
	}
	logger.Infof("[ThreatIntel] [%s] Fetched %d bytes", sourceID, len(data))

	// 2. 解析数据
	parsed, err := m.parser.Parse(data, source.Format, sourceID)
	if err != nil {
		return err
	}
	logger.Infof("[ThreatIntel] [%s] Parsed %d rules (exact: %d, cidr: %d)",
		sourceID, parsed.TotalCount(), len(parsed.IPv4Exact), len(parsed.IPv4CIDR))

	// 3. 同步到内核（传递来源掩码）
	sourceMask := sourceIDToMask(sourceID)
	if err := m.syncer.SyncToKernel(parsed, sourceMask); err != nil {
		return err
	}

	// 4. 更新状态
	m.updateSourceStatus(sourceID, true, parsed.TotalCount(), "")

	return nil
}

// loadFromCache 从本地缓存加载威胁情报（离线启动支持）
// 注意：此函数在 Start() 的 m.mu 锁保护下调用，不能再次获取 m.mu
func (m *Manager) loadFromCache() error {
	if !m.cache.Exists() {
		return ErrThreatIntelCacheNotFound
	}

	cacheData, err := m.cache.Load()
	if err != nil {
		return err
	}

	logger.Infof("[ThreatIntel] Loading cache with %d sources...", len(cacheData.Sources))

	// 在 Start() 的 m.mu 锁保护下，直接更新状态（避免重复获取锁）
	now := time.Now()
	m.lastUpdate = time.Unix(cacheData.Timestamp, 0)

	// 加载每个源的数据
	for sourceID, data := range cacheData.Sources {
		logger.Infof("[ThreatIntel] [%s] Loading %d rules from cache", sourceID, data.TotalCount())

		sourceMask := sourceIDToMask(sourceID)
		if err := m.syncer.LoadAll(&data, sourceMask); err != nil {
			logger.Warnf("[ThreatIntel] [%s] Failed to load from cache: %v", sourceID, err)
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

// saveCache 保存威胁情报到本地缓存
func (m *Manager) saveCache() error {
	cacheData := NewCacheData()

	m.mu.RLock()
	for sourceID, status := range m.sourceStatus {
		if status.Success && status.RuleCount > 0 {
			// 从内核获取当前规则构建缓存数据
			rules, _ := m.xdp.GetRule()
			data := NewIntelData(sourceID)

			for _, r := range rules {
				// 简单分类（实际应该按源分类）
				if len(r.Key) > 0 {
					if containsCIDR(r.Key) {
						data.AddCIDR(r.Key)
					} else {
						data.AddIPv4(r.Key)
					}
				}
			}
			cacheData.Sources[sourceID] = *data
		}
	}
	m.mu.RUnlock()

	return m.cache.Save(cacheData)
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

	for sourceID, source := range m.config.Sources {
		if source.Enabled {
			sources[SourceID(sourceID)] = source
		}
	}

	return sources
}

// GetStatus 获取威胁情报模块状态
func (m *Manager) GetStatus() *Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 返回副本
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

// Stop 停止威胁情报管理器
func (m *Manager) Stop() {
	logger.Info("[ThreatIntel] Stopping threat intelligence manager...")
	if m.cron != nil {
		m.cron.Stop() // 停止所有 Cron 任务
	}
	close(m.done)
	logger.Info("[ThreatIntel] Stopped")
}

// containsCIDR 检查字符串是否是 CIDR 格式（包含 /）
func containsCIDR(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}

// sourceIDToMask 将 SourceID 转换为来源掩码
// 用于标识规则的来源，支持多来源共存
func sourceIDToMask(sourceID SourceID) uint32 {
	switch sourceID {
	case SourceIpsum:
		return 0x01 // Bit 0: IPSum
	case SourceSpamhaus:
		return 0x02 // Bit 1: Spamhaus
	case SourceManual:
		return 0x04 // Bit 2: Manual (future, for manually added rules)
	case SourceWAF:
		return 0x08 // Bit 3: WAF (future)
	case SourceDDoS:
		return 0x10 // Bit 4: DDoS (future)
	default:
		return 0
	}
}
