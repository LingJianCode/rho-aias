// Package blocklog 阻断日志模块
// 用于记录被 XDP 程序阻断的数据包信息
package blocklog

import (
	"fmt"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/logger"

	"gorm.io/gorm"
)

// BlockRecord 阻断记录
type BlockRecord struct {
	Timestamp   int64  `json:"timestamp"`    // 阻断时间戳 (Unix 纳秒)
	SrcIP       string `json:"src_ip"`       // 源 IP 地址
	DstIP       string `json:"dst_ip"`       // 目标 IP 地址
	DstPort     uint16 `json:"dst_port"`     // 目标端口 (TCP/UDP)
	MatchType   string `json:"match_type"`   // 匹配类型 (ip4_exact, ip4_cidr, geo_block, etc.)
	RuleSource  string `json:"rule_source"`  // 规则来源 (manual, ipsum, spamhaus, geo)
	CountryCode string `json:"country_code"` // 国家代码 (仅 geo_block 时有值)
	PacketSize  uint32 `json:"packet_size"`  // 数据包大小
}

// Manager 阻断日志管理器
type Manager struct {
	asyncWriter *AsyncWriter
	statsStore  *StatsStore   // 统计存储（可选）
	geoEnricher *GeoEnricher  // IP 归属地补全器（可选）
}

// NewManager 创建新的阻断日志管理器
func NewManager() *Manager {
	return &Manager{}
}

// NewManagerWithPersistence 创建带持久化的阻断日志管理器
func NewManagerWithPersistence(config Config, db *gorm.DB) (*Manager, error) {
	m := NewManager()

	// 创建异步写入器（注入 onRotate 回调 + db）
	asyncWriter, err := NewAsyncWriter(config, db, func(t time.Time) {
		m.RotateHourlyStats(t)
	})
	if err != nil {
		return nil, err
	}
	m.asyncWriter = asyncWriter

	// 注入统计存储
	if db != nil {
		m.statsStore = NewStatsStore(db)
		// 注入 statsStore 到 AsyncWriter 用于定时清理
		m.asyncWriter.statsStore = m.statsStore
	}

	return m, nil
}

// AddRecord 添加阻断记录
func (m *Manager) AddRecord(record BlockRecord) {
	// 异步写入 SQLite
	if m.asyncWriter != nil {
		if err := m.asyncWriter.Write(record); err != nil {
			logger.Warnf("async write failed: %v", err)
		}
	}
}

// QueryRecords 从 SQLite 按天分表分页查询记录
func (m *Manager) QueryRecords(filter RecordFilter) (*PageResult, error) {
	if m.statsStore == nil {
		return nil, fmt.Errorf("stats store not initialized")
	}
	return m.statsStore.QueryRecords(filter)
}

// RecordFilter 记录过滤条件
type RecordFilter struct {
	Date        string `form:"date"`         // 日期查询 (格式: 2026-04-17)
	StartHour   *int   `form:"start_hour"`   // 起始小时 (0-23, 默认 0)
	EndHour     *int   `form:"end_hour"`     // 结束小时 (0-23, 默认 23)
	MatchType   string `form:"match_type"`   // 匹配类型过滤
	RuleSource  string `form:"rule_source"`  // 规则来源过滤
	SrcIP       string `form:"src_ip"`       // 源 IP 过滤
	CountryCode string `form:"country_code"` // 国家代码过滤
	Page        int    `form:"page"`         // 页码 (从1开始)
	PageSize    int    `form:"page_size"`    // 每页数量
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

// PageResult 分页查询结果
type PageResult struct {
	Records  []BlockRecord `json:"records"`
	Total    int           `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
}

// defaultRetentionDays 默认查询最近天数
const defaultRetentionDays = 30

// GetStats 获取统计信息（纯 DB 查询：历史预聚合 + 当前小时实时 SQL 聚合）
func (m *Manager) GetStats() Stats {
	if m.statsStore == nil {
		return Stats{}
	}

	// 从 DB 获取历史数据（blocklog_hourly_stats 预聚合）
	dbStats := m.statsStore.GetAggregatedStats(defaultRetentionDays)

	// 当前小时：从分表实时 SQL 聚合
	currentHourKey := time.Now().Format("2006-01-02T15")
	currentStats := m.statsStore.AggregateStatsFromTable(currentHourKey)

	// 合并
	dbStats.TotalBlocked += currentStats.TotalBlocked
	for k, v := range currentStats.ByRuleSource {
		dbStats.ByRuleSource[k] += v
	}

	return dbStats
}

// RotateHourlyStats 整点轮转：从分表 SQL 聚合上一小时统计并写入 blocklog_hourly_stats
// 由 cron 定时任务在每小时第 3 分钟调用，聚合上一小时数据
func (m *Manager) RotateHourlyStats(t time.Time) {
	if m.statsStore == nil {
		return
	}
	hourKey := t.Format("2006-01-02T15")
	stats := m.statsStore.AggregateStatsFromTable(hourKey)
	topIPs := m.statsStore.AggregateTopIPsFromTable(hourKey)

	if stats.TotalBlocked > 0 || len(topIPs) > 0 {
		m.statsStore.SnapshotHour(hourKey, stats, topIPs)
	}
}

// Close 关闭阻断日志管理器（停止异步写入器）
func (m *Manager) Close() error {
	if m.geoEnricher != nil {
		m.geoEnricher.Stop()
	}
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

// SetGeoLookup 注入 GeoLookup 并启动 IP 归属地补全定时任务（由 bootstrap 调用）
func (m *Manager) SetGeoLookup(lookup GeoLookup, cfg config.GeoEnrichConfig) {
	if m.statsStore == nil || lookup == nil {
		logger.Info("[BlockLog] GeoLookup not available, skipping geo enrich setup")
		return
	}

	m.geoEnricher = NewGeoEnricher(m.statsStore, lookup, cfg.Enabled, cfg.BatchSize)
	if err := m.geoEnricher.Start(); err != nil {
		logger.Errorf("[BlockLog] Failed to start geo enricher: %v", err)
	}
}

// EnrichCountryCode 手动触发按天补全（异步，供 handle 调用）
func (m *Manager) EnrichCountryCode(date string) error {
	if m.geoEnricher == nil {
		return fmt.Errorf("geo enricher not initialized")
	}
	return m.geoEnricher.EnrichDay(date)
}

// CreateRecord 创建阻断记录的便捷方法
func CreateRecord(srcIP, dstIP, matchType, ruleSource, countryCode string, dstPort uint16, packetSize uint32) BlockRecord {
	return BlockRecord{
		Timestamp:   time.Now().UnixNano(),
		SrcIP:       srcIP,
		DstIP:       dstIP,
		DstPort:     dstPort,
		MatchType:   matchType,
		RuleSource:  ruleSource,
		CountryCode: countryCode,
		PacketSize:  packetSize,
	}
}
