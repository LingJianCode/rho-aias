package egresslog

import (
	"fmt"
	"strings"
	"time"

	"rho-aias/internal/logger"
	"rho-aias/internal/models"

	"gorm.io/gorm"
)

// StatsStore 基于 GORM 的 Egress 丢包统计持久化存储
type StatsStore struct {
	db *gorm.DB
}

// HourlyTrendItem 单小时趋势数据
type HourlyTrendItem struct {
	Hour      string           `json:"hour"`      // 格式: "2026-04-10T14"
	Total     int64            `json:"total"`     // 该小时总计数
	Breakdown map[string]int64 `json:"breakdown"` // 按目标 IP 细分
}

// NewStatsStore 创建统计存储实例
func NewStatsStore(db *gorm.DB) *StatsStore {
	return &StatsStore{db: db}
}

// QueryRecords 从按天分表查询丢包记录
func (ss *StatsStore) QueryRecords(filter RecordFilter) (*PageResult, error) {
	if ss.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	parsedDate, err := time.Parse("2006-01-02", filter.Date)
	if err != nil {
		return nil, fmt.Errorf("invalid date format, expected YYYY-MM-DD, got: %s", filter.Date)
	}

	tableName := "egresslog_" + parsedDate.Format("20060102")

	if !ss.db.Migrator().HasTable(tableName) {
		return &PageResult{
			Records:  []DropRecord{},
			Total:    0,
			Page:     filter.Page,
			PageSize: filter.PageSize,
		}, nil
	}

	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}

	startHour := 0
	if filter.StartHour != nil {
		startHour = *filter.StartHour
	}
	if startHour < 0 || startHour > 23 {
		startHour = 0
	}
	endHour := 23
	if filter.EndHour != nil {
		endHour = *filter.EndHour
	}
	if endHour < 0 || endHour > 23 {
		endHour = 23
	}

	query := ss.db.Table(tableName).Where("hour BETWEEN ? AND ?", startHour, endHour)

	if filter.DstIP != "" {
		query = query.Where("dst_ip = ?", filter.DstIP)
	}

	var total int64
	query.Count(&total)

	var rows []models.EgresslogRecord
	offset := (page - 1) * pageSize
	if err := query.Order("id DESC").Offset(offset).Limit(pageSize).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("query records failed: %w", err)
	}

	records := make([]DropRecord, len(rows))
	for i, r := range rows {
		records[i] = DropRecord{
			Timestamp: r.Timestamp,
			DstIP:     r.DstIP,
			PktLen:    r.PktLen,
			Tokens:    r.Tokens,
			RateBytes: r.RateBytes,
		}
	}

	return &PageResult{
		Records:  records,
		Total:    int(total),
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// AggregateTopIPsFromTable 从按天分表聚合 Top IP
func (ss *StatsStore) AggregateTopIPsFromTable(hourKey string) []IPCount {
	if ss.db == nil {
		return nil
	}

	parts := strings.SplitN(hourKey, "T", 2)
	if len(parts) != 2 {
		return nil
	}

	dateStr := parts[0]
	hourStr := parts[1]

	parsedDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return nil
	}

	tableName := "egresslog_" + parsedDate.Format("20060102")
	if !ss.db.Migrator().HasTable(tableName) {
		return nil
	}

	var hour int
	fmt.Sscanf(hourStr, "%d", &hour)

	var results []struct {
		DstIP string `json:"dst_ip"`
		Count int64  `json:"count"`
	}

	ss.db.Table(tableName).
		Select("dst_ip, COUNT(*) as count").
		Where("hour = ?", hour).
		Group("dst_ip").
		Having("COUNT(*) > 1").
		Order("count DESC").
		Limit(20).
		Find(&results)

	if len(results) == 0 {
		return nil
	}

	ips := make([]IPCount, len(results))
	for i, r := range results {
		ips[i] = IPCount{IP: r.DstIP, Count: int(r.Count)}
	}
	return ips
}

// AggregateStatsFromTable 从按天分表 SQL 聚合指定小时的统计数据
func (ss *StatsStore) AggregateStatsFromTable(hourKey string) Stats {
	if ss.db == nil {
		return Stats{}
	}

	parts := strings.SplitN(hourKey, "T", 2)
	if len(parts) != 2 {
		return Stats{}
	}

	dateStr := parts[0]
	hourStr := parts[1]

	parsedDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return Stats{}
	}

	tableName := "egresslog_" + parsedDate.Format("20060102")
	if !ss.db.Migrator().HasTable(tableName) {
		return Stats{}
	}

	var hour int
	fmt.Sscanf(hourStr, "%d", &hour)

	stats := Stats{
		ByDstIP: make(map[string]int),
	}

	var results []struct {
		DstIP string `json:"dst_ip"`
		Count int64  `json:"count"`
	}

	ss.db.Table(tableName).
		Select("dst_ip, COUNT(*) as count").
		Where("hour = ?", hour).
		Group("dst_ip").
		Order("count DESC").
		Limit(20).
		Find(&results)

	for _, r := range results {
		stats.ByDstIP[r.DstIP] = int(r.Count)
		stats.TotalDropped += int(r.Count)
	}

	return stats
}

// CleanupOldDayTables 清理 N 天前的按天分表（DROP TABLE）
func (ss *StatsStore) CleanupOldDayTables(retainDays int) error {
	if ss.db == nil {
		return nil
	}

	cutoffDate := time.Now().AddDate(0, 0, -retainDays)

	var tableNames []string
	if err := ss.db.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'egresslog_2%'").Scan(&tableNames).Error; err != nil {
		return fmt.Errorf("query sqlite_master failed: %w", err)
	}

	dropped := 0
	for _, name := range tableNames {
		dateStr := strings.TrimPrefix(name, "egresslog_")
		if len(dateStr) != 8 {
			continue
		}

		parsed, err := time.Parse("20060102", dateStr)
		if err != nil {
			continue
		}

		if parsed.Before(cutoffDate) {
			if err := ss.db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", name)).Error; err != nil {
				logger.Warnf("[EgressLog] Failed to drop table %s: %v", name, err)
			} else {
				dropped++
				logger.Infof("[EgressLog] Dropped old daily table: %s", name)
			}
		}
	}

	logger.Infof("[EgressLog] Cleaned up %d daily tables older than %d days", dropped, retainDays)
	return nil
}
