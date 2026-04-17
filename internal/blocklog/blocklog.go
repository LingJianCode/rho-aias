// Package blocklog 阻断日志模块
// 用于记录被 XDP 程序阻断的数据包信息
package blocklog

import (
	"fmt"
	"sort"
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
// 仅作为写缓冲区，整点轮转时刷入 DB 后归零，不参与查询
type blockLogCounters struct {
	totalBlocked int64
	byRuleSource map[string]*int64 // 每种规则来源的计数指针
	byCountry    map[string]*int64 // 每个国家的计数指针
	topIPs       map[string]*int64 // 每个 IP 的计数指针
	mu           sync.RWMutex      // 写端保护 map 结构变更，读端 RLock 无阻塞
}

// BlockLog 阻断日志管理器
type BlockLog struct {
	mu          sync.RWMutex
	records     []BlockRecord
	maxSize     int
	asyncWriter *AsyncWriter
	statsStore  *StatsStore    // 统计存储（可选）
	jsonReader  *JsonLogReader // JSONL 文件查询器
	counters    *blockLogCounters
}

// NewBlockLog 创建新的阻断日志管理器
func NewBlockLog(maxSize int) *BlockLog {
	return &BlockLog{
		records:  make([]BlockRecord, 0, maxSize),
		maxSize:  maxSize,
		counters: newBlockLogCounters(),
	}
}

// newBlockLogCounters 创建增量统计计数器
func newBlockLogCounters() *blockLogCounters {
	return &blockLogCounters{
		byRuleSource: make(map[string]*int64),
		byCountry:    make(map[string]*int64),
		topIPs:       make(map[string]*int64),
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
		TotalBlocked:        int(atomic.LoadInt64(&c.totalBlocked)),
		ByRuleSource:        make(map[string]int),
		ByCountry:           make(map[string]int),
		TopBlockedIPs:       []IPCount{},
		TopBlockedCountries: []CountryCount{},
	}

	c.mu.RLock()
	for k, v := range c.byRuleSource {
		if cnt := atomic.LoadInt64(v); cnt > 0 {
			stats.ByRuleSource[k] = int(cnt)
		}
	}
	for k, v := range c.byCountry {
		if cnt := atomic.LoadInt64(v); cnt > 0 {
			stats.ByCountry[k] = int(cnt)
		}
	}
	for k, v := range c.topIPs {
		if cnt := atomic.LoadInt64(v); cnt > 0 {
			stats.TopBlockedIPs = append(stats.TopBlockedIPs, IPCount{IP: k, Count: int(cnt)})
		}
	}
	c.mu.RUnlock()

	sort.Slice(stats.TopBlockedIPs, func(i, j int) bool {
		return stats.TopBlockedIPs[i].Count > stats.TopBlockedIPs[j].Count
	})
	if len(stats.TopBlockedIPs) > 50 {
		stats.TopBlockedIPs = stats.TopBlockedIPs[:50]
	}

	// 国家 Top 排序
	type cn struct {
		Country string
		Count   int
	}
	var countries []cn
	for country, count := range stats.ByCountry {
		countries = append(countries, cn{country, count})
	}
	sort.Slice(countries, func(i, j int) bool { return countries[i].Count > countries[j].Count })
	stats.TopBlockedCountries = make([]CountryCount, len(countries))
	for i, c := range countries {
		stats.TopBlockedCountries[i] = CountryCount(c)
	}

	return stats
}

// reset 重置所有计数器（整点轮转刷入 DB 后调用）
func (c *blockLogCounters) reset() {
	atomic.StoreInt64(&c.totalBlocked, 0)

	c.mu.Lock()
	c.byRuleSource = make(map[string]*int64)
	c.byCountry = make(map[string]*int64)
	c.topIPs = make(map[string]*int64)
	c.mu.Unlock()
}

// NewBlockLogWithPersistence 创建带持久化的阻断日志管理器
// StatsStore 延迟注入，由调用方在 bizDB 就绪后通过 AttachStatsStore 注入
func NewBlockLogWithPersistence(maxSize int, config Config) (*BlockLog, error) {
	bl := NewBlockLog(maxSize)

	// 创建异步写入器（注入 onRotate 回调）
	asyncWriter, err := NewAsyncWriter(config, func(t time.Time) {
		bl.SnapshotHourlyCounters(t)
	})
	if err != nil {
		return nil, err
	}
	bl.asyncWriter = asyncWriter

	// 创建 JSONL 查询器（复用同一个 logDir）
	bl.jsonReader = NewJsonLogReader(config.LogDir)

	// StatsStore 不再在此创建，等待 AttachStatsStore 注入

	return bl, nil
}

// AttachStatsStore 注入统计存储（需在业务数据库初始化后调用）
func (bl *BlockLog) AttachStatsStore(db *gorm.DB) {
	bl.statsStore = NewStatsStore(db)
}

// AddRecord 添加阻断记录
func (bl *BlockLog) AddRecord(record BlockRecord) {
	bl.mu.Lock()

	// 如果超过最大记录数，删除最旧的记录
	// 使用 copy 而非 slice 重切，避免底层数组无限增长导致内存泄漏
	if len(bl.records) >= bl.maxSize {
		copy(bl.records, bl.records[1:])
		bl.records = bl.records[:len(bl.records)-1]
	}

	bl.records = append(bl.records, record)

	// 异步写入文件（Write 是非阻塞的，可以安全地在锁内调用）
	if bl.asyncWriter != nil {
		if err := bl.asyncWriter.Write(record); err != nil {
			logger.Warnf("async write failed: %v", err)
		}
	}

	bl.mu.Unlock()

	// 增量计数器更新（原子操作，无锁，仅用于整点轮转时的写缓冲）
	if bl.counters != nil {
		c := bl.counters
		atomic.AddInt64(&c.totalBlocked, 1)
		c.increment(c.byRuleSource, record.RuleSource)
		c.increment(c.byCountry, record.CountryCode)
		c.increment(c.topIPs, record.SrcIP)
	}
}

// GetRecords 获取阻断记录
// limit: 返回记录数量限制，0 表示返回所有
func (bl *BlockLog) GetRecords(limit int) []BlockRecord {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	if limit <= 0 || limit > len(bl.records) {
		limit = len(bl.records)
	}

	// 返回最近的记录（从后往前）
	result := make([]BlockRecord, limit)
	for i := 0; i < limit; i++ {
		result[i] = bl.records[len(bl.records)-1-i]
	}

	return result
}

// GetRecordsByFilter 按条件筛选阻断记录（内存查询）
func (bl *BlockLog) GetRecordsByFilter(filter RecordFilter) []BlockRecord {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	var result []BlockRecord

	// 从后往前遍历（最新的记录优先）
	for i := len(bl.records) - 1; i >= 0; i-- {
		record := bl.records[i]

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
func (bl *BlockLog) QueryJSONLRecords(filter RecordFilter) (*PageResult, error) {
	if bl.jsonReader == nil {
		return nil, fmt.Errorf("json reader not initialized")
	}
	return bl.jsonReader.QueryPage(filter.Hour, filter)
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
	TotalBlocked        int            `json:"total_blocked"`         // 总阻断数
	ByRuleSource        map[string]int `json:"by_rule_source"`        // 按规则来源统计
	ByCountry           map[string]int `json:"by_country"`            // 按国家统计
	TopBlockedIPs       []IPCount      `json:"top_blocked_ips"`       // 被阻断最多的 IP
	TopBlockedCountries []CountryCount `json:"top_blocked_countries"` // 被阻断最多的国家
}

// IPCount IP 计数
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// CountryCount 国家计数
type CountryCount struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// GetStats 获取统计信息（纯 DB 查询）
func (bl *BlockLog) GetStats() Stats {
	if bl.statsStore != nil {
		return bl.statsStore.GetAggregatedStats()
	}
	return Stats{}
}

// SnapshotHourlyCounters 将当前内存计数器快照写入 DB 并重置（整点轮转时由回调调用）
func (bl *BlockLog) SnapshotHourlyCounters(t time.Time) {
	if bl.counters == nil || bl.statsStore == nil {
		return
	}
	hourKey := t.Format("2006-01-02T15")
	snap := bl.counters.snapshot()
	if snap.TotalBlocked > 0 {
		bl.statsStore.SnapshotHour(hourKey, snap)
	}
	bl.counters.reset()
}

// Close 关闭阻断日志管理器（停止异步写入器）
func (bl *BlockLog) Close() error {
	if bl.asyncWriter != nil {
		return bl.asyncWriter.Stop()
	}
	return nil
}

// GetHourlyTrend 获取丢弃计数的小时趋势
func (bl *BlockLog) GetHourlyTrend(hours int) []HourlyTrendItem {
	if bl.statsStore == nil {
		return nil
	}
	return bl.statsStore.GetHourlyTrend(hours)
}

// GetTopIPs 从数据库查询 Top N 被阻断 IP
func (bl *BlockLog) GetTopIPs(limit int) ([]IPCount, int64) {
	if bl.statsStore == nil {
		return nil, 0
	}
	return bl.statsStore.GetTopIPs(limit)
}

// GetTopCountries 从数据库查询 Top N 被阻断国家
func (bl *BlockLog) GetTopCountries(limit int) ([]CountryCount, int) {
	if bl.statsStore == nil {
		return nil, 0
	}
	return bl.statsStore.GetTopCountries(limit)
}

// Flush 刷新缓冲区到磁盘
func (bl *BlockLog) Flush() error {
	if bl.asyncWriter != nil {
		return bl.asyncWriter.Flush()
	}
	return nil
}

// Count 获取记录总数
func (bl *BlockLog) Count() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	return len(bl.records)
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
