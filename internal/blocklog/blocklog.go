// Package blocklog 阻断日志模块
// 用于记录被 XDP 程序阻断的数据包信息
package blocklog

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"rho-aias/internal/logger"
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
type blockLogCounters struct {
	totalBlocked int64
	byMatchType  map[string]*int64 // 每种匹配类型的计数指针
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
	statsStore  *StatsStore // 统计存储（可选）
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
		byMatchType:  make(map[string]*int64),
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

// reset 重置所有计数器（Clear 时使用）
func (c *blockLogCounters) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.totalBlocked = 0
	for _, v := range c.byMatchType {
		atomic.StoreInt64(v, 0)
	}
	for _, v := range c.byRuleSource {
		atomic.StoreInt64(v, 0)
	}
	for _, v := range c.byCountry {
		atomic.StoreInt64(v, 0)
	}
	for _, v := range c.topIPs {
		atomic.StoreInt64(v, 0)
	}
}

// snapshot 读取当前计数器快照（用于 GetStats）
func (c *blockLogCounters) snapshot() Stats {
	stats := Stats{
		TotalBlocked:        int(atomic.LoadInt64(&c.totalBlocked)),
		ByMatchType:         make(map[string]int),
		ByRuleSource:        make(map[string]int),
		ByCountry:           make(map[string]int),
		TopBlockedIPs:       []IPCount{},
		TopBlockedCountries: []CountryCount{},
	}

	c.mu.RLock()
	for k, v := range c.byMatchType {
		if cnt := atomic.LoadInt64(v); cnt > 0 {
			stats.ByMatchType[k] = int(cnt)
		}
	}
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
	if len(stats.TopBlockedIPs) > 10 {
		stats.TopBlockedIPs = stats.TopBlockedIPs[:10]
	}

	// 国家 Top 排序
	type cn struct{ Country string; Count int }
	var countries []cn
	for country, count := range stats.ByCountry {
		countries = append(countries, cn{country, count})
	}
	sort.Slice(countries, func(i, j int) bool { return countries[i].Count > countries[j].Count })
	if len(countries) > 10 { countries = countries[:10] }
	stats.TopBlockedCountries = make([]CountryCount, len(countries))
	for i, c := range countries {
		stats.TopBlockedCountries[i] = CountryCount(c)
	}

	return stats
}

// NewBlockLogWithPersistence 创建带持久化的阻断日志管理器
func NewBlockLogWithPersistence(maxSize int, config Config) (*BlockLog, error) {
	bl := NewBlockLog(maxSize)

	// 创建异步写入器
	asyncWriter, err := NewAsyncWriter(config)
	if err != nil {
		return nil, err
	}
	bl.asyncWriter = asyncWriter

	// 初始化统计存储（SQLite，失败不阻塞启动）
	statsStore, err := NewStatsStore(config.LogDir)
	if err != nil {
		logger.Warnf("[BlockLog] init stats store failed (non-fatal): %v", err)
	} else {
		bl.statsStore = statsStore
	}

	return bl, nil
}

// AddRecord 添加阻断记录
func (bl *BlockLog) AddRecord(record BlockRecord) {
	// 统计写入在锁外执行（SQLite 磁盘 I/O），避免阻塞热路径
	var ruleSource string
	if bl.statsStore != nil {
		ruleSource = record.RuleSource
	}

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

	// 增量计数器更新（原子操作，无锁，与 records slice 解耦）
	if bl.counters != nil {
		c := bl.counters
		atomic.AddInt64(&c.totalBlocked, 1)
		c.increment(c.byMatchType, record.MatchType)
		c.increment(c.byRuleSource, record.RuleSource)
		c.increment(c.byCountry, record.CountryCode)
		c.increment(c.topIPs, record.SrcIP)
	}

	// 统计存储写操作移至锁外（SQLite INSERT），避免 DDoS 场景下锁争用
	if ruleSource != "" {
		bl.statsStore.Record(ruleSource)
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

// GetRecordsByFilter 按条件筛选阻断记录
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

// RecordFilter 记录过滤条件
type RecordFilter struct {
	MatchType   string `form:"match_type"`   // 匹配类型过滤
	RuleSource  string `form:"rule_source"`  // 规则来源过滤
	SrcIP       string `form:"src_ip"`       // 源 IP 过滤
	CountryCode string `form:"country_code"` // 国家代码过滤
	Limit       int    `form:"limit"`        // 返回数量限制
}

// Stats 统计信息
type Stats struct {
	TotalBlocked        int            `json:"total_blocked"`         // 总阻断数
	ByMatchType         map[string]int `json:"by_match_type"`         // 按匹配类型统计
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

// GetStats 获取统计信息（使用增量计数器快照，O(1) 无需遍历 records）
func (bl *BlockLog) GetStats() Stats {
	if bl.counters != nil {
		return bl.counters.snapshot()
	}
	return Stats{}
}

// Clear 清空所有记录
func (bl *BlockLog) Clear() {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	bl.records = make([]BlockRecord, 0, bl.maxSize)
	if bl.counters != nil {
		bl.counters.reset()
	}
}

// Close 关闭阻断日志管理器（停止异步写入器、关闭统计存储）
func (bl *BlockLog) Close() error {
	if bl.statsStore != nil {
		bl.statsStore.Close()
	}
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

// GetDroppedSummary 获取丢弃概览
func (bl *BlockLog) GetDroppedSummary(hours int) DroppedSummary {
	if bl.statsStore == nil {
		return DroppedSummary{}
	}
	return bl.statsStore.GetDroppedSummary(hours)
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
