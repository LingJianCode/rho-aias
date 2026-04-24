// Package egresslog Egress 丢包日志模块
// 用于记录被 TC egress 限速丢弃的数据包信息
package egresslog

import (
	"fmt"
	"time"

	"rho-aias/internal/config"
	"rho-aias/internal/logger"

	"gorm.io/gorm"
)

// DropRecord 丢包记录
type DropRecord struct {
	Timestamp int64  `json:"timestamp"`  // 丢包时间戳 (Unix 纳秒)
	DstIP     string `json:"dst_ip"`     // 目标 IP 地址
	PktLen    uint32 `json:"pkt_len"`    // 被丢弃的包大小 (Bytes)
	Tokens    uint64 `json:"tokens"`     // 丢包时令牌数 (诊断用)
	RateBytes uint64 `json:"rate_bytes"` // 当时限速速率 (诊断用)
}

// Manager Egress 丢包日志管理器
type Manager struct {
	asyncWriter *AsyncWriter
	statsStore  *StatsStore
}

// NewManager 创建新的丢包日志管理器
func NewManager() *Manager {
	return &Manager{}
}

// NewManagerWithPersistence 创建带持久化的丢包日志管理器
func NewManagerWithPersistence(cfg Config, db *gorm.DB) (*Manager, error) {
	m := NewManager()

	// 创建异步写入器（注入 onRotate 回调 + db）
	asyncWriter, err := NewAsyncWriter(cfg, db, nil)
	if err != nil {
		return nil, err
	}
	m.asyncWriter = asyncWriter

	// 注入统计存储
	if db != nil {
		m.statsStore = NewStatsStore(db)
		m.asyncWriter.statsStore = m.statsStore
	}

	return m, nil
}

// AddRecord 添加丢包记录
func (m *Manager) AddRecord(record DropRecord) {
	if m.asyncWriter != nil {
		if err := m.asyncWriter.Write(record); err != nil {
			logger.Warnf("[EgressLog] async write failed: %v", err)
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
	Date      string `form:"date"`       // 日期查询 (格式: 2026-04-17)
	StartHour *int   `form:"start_hour"` // 起始小时 (0-23, 默认 0)
	EndHour   *int   `form:"end_hour"`   // 结束小时 (0-23, 默认 23)
	DstIP     string `form:"dst_ip"`     // 目标 IP 过滤
	Page      int    `form:"page"`       // 页码 (从1开始)
	PageSize  int    `form:"page_size"`  // 每页数量
}

// Stats 统计信息
type Stats struct {
	TotalDropped int            `json:"total_dropped"` // 总丢包数
	ByDstIP      map[string]int `json:"by_dst_ip"`     // 按目标 IP 统计 (Top N)
}

// IPCount IP 计数
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// PageResult 分页查询结果
type PageResult struct {
	Records  []DropRecord `json:"records"`
	Total    int          `json:"total"`
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
}

// defaultRetentionDays 默认查询最近天数
const defaultRetentionDays = 30

// Close 关闭管理器
func (m *Manager) Close() error {
	if m.asyncWriter != nil {
		return m.asyncWriter.Stop()
	}
	return nil
}

// Flush 刷新缓冲区到磁盘
func (m *Manager) Flush() error {
	if m.asyncWriter != nil {
		return m.asyncWriter.Flush()
	}
	return nil
}

// CreateDropRecord 创建丢包记录的便捷方法
func CreateDropRecord(dstIP string, pktLen uint32, tokens, rateBytes uint64) DropRecord {
	return DropRecord{
		Timestamp: time.Now().UnixNano(),
		DstIP:     dstIP,
		PktLen:    pktLen,
		Tokens:    tokens,
		RateBytes: rateBytes,
	}
}

// ConfigFromYaml 从 YAML 配置创建 AsyncWriter 配置
func ConfigFromYaml(cfg config.EgressLimitConfig) Config {
	return Config{
		BufferSize:    1000,
		FlushInterval: time.Duration(5) * time.Second,
	}
}
