// Package blocklog 阻断日志模块
// 用于记录被 XDP 程序阻断的数据包信息
package blocklog

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"rho-aias/internal/logger"

	"gorm.io/gorm"
)

// BlockRecord 阻断记录
type BlockRecord struct {
	Timestamp   int64  `json:"timestamp"`    // 阻断时间戳 (Unix 纳秒)
	SrcIP       string `json:"src_ip"`       // 源 IP 地址
	DstIP       string `json:"dst_ip"`       // 目标 IP 地址
	MatchType   string `json:"match_type"`   // 匹配类型 (ip4_exact, ip4_cidr, geo_block, etc.)
	RuleSource  string `json:"rule_source"`  // 规则来源 (manual, ipsum, spamhaus, geo)
	CountryCode string `json:"country_code"` // 国家代码 (仅 geo_block 时有值)
	PacketSize  uint32 `json:"packet_size"`  // 数据包大小
}

// blockLogCounters 增量统计计数器（原子操作，无锁热路径）
// 整点轮转时刷入 DB 后归零；查询时通过融合查询（DB + 内存快照）实现实时统计
type blockLogCounters struct {
	totalBlocked int64
	byRuleSource map[string]*int64 // 每种规则来源的计数指针
	mu           sync.RWMutex      // 写端保护 map 结构变更，读端 RLock 无阻塞
}

// Manager 阻断日志管理器
type Manager struct {
	mu          sync.RWMutex
	records     []BlockRecord
	maxSize     int
	asyncWriter *AsyncWriter
	statsStore  *StatsStore    // 统计存储（可选）
	jsonReader  *JsonLogReader // JSONL 文件查询器
	counters    *blockLogCounters
}

// NewManager 创建新的阻断日志管理器
func NewManager(maxSize int) *Manager {
	return &Manager{
		records:  make([]BlockRecord, 0, maxSize),
		maxSize:  maxSize,
		counters: newBlockLogCounters(),
	}
}

// newBlockLogCounters 创建增量统计计数器
func newBlockLogCounters() *blockLogCounters {
	return &blockLogCounters{
		byRuleSource: make(map[string]*int64),
	}
}

// increment 安全地递增计数器（不包含总计数）
func (c *blockLogCounters) increment(m map[string]*int64, key string) {
	if key == "" {
		return
	}
	// 先尝试无锁读，命中则直接原子加；未命中才走锁路径
	c.mu.Lock()
	ptr, ok := m[key]
	if !ok {
		var v int64 = 0
		ptr = &v
		m[key] = ptr
	}
	c.mu.Unlock()
	atomic.AddInt64(ptr, 1)
}

// snapshot 读取当前计数器快照（用于整点轮转时刷入 DB）
func (c *blockLogCounters) snapshot() Stats {
	stats := Stats{
		TotalBlocked: int(atomic.LoadInt64(&c.totalBlocked)),
		ByRuleSource: make(map[string]int),
	}

	c.mu.RLock()
	for k, v := range c.byRuleSource {
		if cnt := atomic.LoadInt64(v); cnt > 0 {
			stats.ByRuleSource[k] = int(cnt)
		}
	}
	c.mu.RUnlock()

	return stats
}

// reset 重置所有计数器（整点轮转刷入 DB 后调用）
func (c *blockLogCounters) reset() {
	atomic.StoreInt64(&c.totalBlocked, 0)

	c.mu.Lock()
	c.byRuleSource = make(map[string]*int64)
	c.mu.Unlock()
}

// NewManagerWithPersistence 创建带持久化的阻断日志管理器
func NewManagerWithPersistence(maxSize int, config Config, db *gorm.DB) (*Manager, error) {
	m := NewManager(maxSize)

	// 创建异步写入器（注入 onRotate 回调）
	asyncWriter, err := NewAsyncWriter(config, func(t time.Time) {
		m.SnapshotHourlyCounters(t)
	})
	if err != nil {
		return nil, err
	}
	m.asyncWriter = asyncWriter

	// 创建 JSONL 查询器（复用同一个 logDir）
	m.jsonReader = NewJsonLogReader(config.LogDir)

	// 注入统计存储
	if db != nil {
		m.statsStore = NewStatsStore(db)
	}

	return m, nil
}

// AddRecord 添加阻断记录
func (m *Manager) AddRecord(record BlockRecord) {
	m.mu.Lock()

	// 如果超过最大记录数，删除最旧的记录
	// 使用 copy 而非 slice 重切，避免底层数组无限增长导致内存泄漏
	if len(m.records) >= m.maxSize {
		copy(m.records, m.records[1:])
		m.records = m.records[:len(m.records)-1]
	}

	m.records = append(m.records, record)

	// 异步写入文件（Write 是非阻塞的，可以安全地在锁内调用）
	if m.asyncWriter != nil {
		if err := m.asyncWriter.Write(record); err != nil {
			logger.Warnf("async write failed: %v", err)
		}
	}

	m.mu.Unlock()

	// 增量计数器更新（原子操作，无锁，仅用于整点轮转时的写缓冲）
	if m.counters != nil {
		c := m.counters
		atomic.AddInt64(&c.totalBlocked, 1)
		c.increment(c.byRuleSource, record.RuleSource)
	}
}

// GetRecords 获取阻断记录
// limit: 返回记录数量限制，0 表示返回所有
func (m *Manager) GetRecords(limit int) []BlockRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.records) {
		limit = len(m.records)
	}

	// 返回最近的记录（从后往前）
	result := make([]BlockRecord, limit)
	for i := 0; i < limit; i++ {
		result[i] = m.records[len(m.records)-1-i]
	}

	return result
}

// GetRecordsByFilter 按条件筛选阻断记录（内存查询）
func (m *Manager) GetRecordsByFilter(filter RecordFilter) []BlockRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []BlockRecord

	// 从后往前遍历（最新的记录优先）
	for i := len(m.records) - 1; i >= 0; i-- {
		record := m.records[i]

		// 应用过滤条件
		if filter.MatchType != "" && record.MatchType != filter.MatchType {
			continue
		}
		if filter.RuleSource != "" && record.RuleSource != filter.RuleSource {
			continue
		}
		if filter.SrcIP != "" && record.SrcIP != filter.SrcIP {
			continue
		}
		if filter.CountryCode != "" && record.CountryCode != filter.CountryCode {
			continue
		}

		result = append(result, record)

		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}

	return result
}

// QueryJSONLRecords 从 JSONL 文件分页查询记录
func (m *Manager) QueryJSONLRecords(filter RecordFilter) (*PageResult, error) {
	if m.jsonReader == nil {
		return nil, fmt.Errorf("json reader not initialized")
	}
	return m.jsonReader.QueryPage(filter.Hour, filter)
}

// RecordFilter 记录过滤条件
type RecordFilter struct {
	Hour        string `form:"hour"`         // 小时查询 (格式: 2026-04-17_14)
	MatchType   string `form:"match_type"`   // 匹配类型过滤
	RuleSource  string `form:"rule_source"`  // 规则来源过滤
	SrcIP       string `form:"src_ip"`       // 源 IP 过滤
	CountryCode string `form:"country_code"` // 国家代码过滤
	Page        int    `form:"page"`         // 页码 (从1开始)
	PageSize    int    `form:"page_size"`    // 每页数量
	Limit       int    `form:"limit"`        // 返回数量限制 (内存查询模式)
}

// Stats 统计信息
type Stats struct {
	TotalBlocked int            `json:"total_blocked"`  // 总阻断数
	ByRuleSource map[string]int `json:"by_rule_source"` // 按规则来源统计
}

// IPCount IP 计数
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// defaultRetentionDays 默认查询最近天数
const defaultRetentionDays = 30

// GetStats 获取统计信息（融合查询：DB 历史数据 + 内存实时计数器）
func (m *Manager) GetStats() Stats {
	if m.statsStore == nil {
		// 无 DB 时直接返回内存快照
		if m.counters != nil {
			return m.counters.snapshot()
		}
		return Stats{}
	}

	// 从 DB 获取历史数据（带时间边界）
	dbStats := m.statsStore.GetAggregatedStats(defaultRetentionDays)

	// 融合内存计数器（当前小时，尚未 flush 到 DB）
	memSnap := m.counters.snapshot()

	// 合并 TotalBlocked
	dbStats.TotalBlocked += memSnap.TotalBlocked

	// 合并 ByRuleSource
	for k, v := range memSnap.ByRuleSource {
		dbStats.ByRuleSource[k] += v
	}

	return dbStats
}

// SnapshotHourlyCounters 将当前内存计数器快照写入 DB 并重置（整点轮转时由回调调用）
func (m *Manager) SnapshotHourlyCounters(t time.Time) {
	if m.counters == nil || m.statsStore == nil {
		return
	}
	hourKey := t.Format("2006-01-02T15")
	snap := m.counters.snapshot()

	// 从 JSONL 文件批量聚合 topIPs（替代内存实时计数，数据最多落后 1 小时）
	var topIPs []IPCount
	if m.jsonReader != nil {
		topIPs = m.jsonReader.AggregateTopIPs(hourKey)
	}

	if snap.TotalBlocked > 0 || len(topIPs) > 0 {
		m.statsStore.SnapshotHour(hourKey, snap, topIPs)
	}
	m.counters.reset()
}

// Close 关闭阻断日志管理器（停止异步写入器）
func (m *Manager) Close() error {
	if m.asyncWriter != nil {
		return m.asyncWriter.Stop()
	}
	return nil
}

// GetHourlyTrend 获取丢弃计数的小时趋势
func (m *Manager) GetHourlyTrend(hours int) []HourlyTrendItem {
	if m.statsStore == nil {
		return nil
	}
	return m.statsStore.GetHourlyTrend(hours)
}

// GetTopIPs 从数据库查询 Top N 被阻断 IP（纯 DB 查询，数据最多落后 1 小时）
func (m *Manager) GetTopIPs(limit int) []IPCount {
	if m.statsStore == nil {
		return nil
	}
	return m.statsStore.GetTopIPs(defaultRetentionDays, limit)
}

// Flush 刷新缓冲区到磁盘
func (m *Manager) Flush() error {
	if m.asyncWriter != nil {
		return m.asyncWriter.Flush()
	}
	return nil
}

// Count 获取记录总数
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.records)
}

// CreateRecord 创建阻断记录的便捷方法
func CreateRecord(srcIP, dstIP, matchType, ruleSource, countryCode string, packetSize uint32) BlockRecord {
	return BlockRecord{
		Timestamp:   time.Now().UnixNano(),
		SrcIP:       srcIP,
		DstIP:       dstIP,
		MatchType:   matchType,
		RuleSource:  ruleSource,
		CountryCode: countryCode,
		PacketSize:  packetSize,
	}
}
