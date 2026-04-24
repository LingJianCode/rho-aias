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

// SnapshotHour 将指定小时的统计快照写入数据库
func (ss *StatsStore) SnapshotHour(hour string, stats Stats, topIPs []IPCount) {
	if ss.db == nil {
		return
	}

	records := []models.EgresslogHourlyStat{}

	records = append(records, models.EgresslogHourlyStat{
		Hour:      hour,
		Dimension: "total",
		DimValue:  "",
		Count:     int64(stats.TotalDropped),
	})

	for ip, cnt := range stats.ByDstIP {
		records = append(records, models.EgresslogHourlyStat{
			Hour:      hour,
			Dimension: "dst_ip",
			DimValue:  ip,
			Count:     int64(cnt),
		})
	}

	for _, rec := range records {
		err := ss.db.Exec(
			`INSERT INTO egresslog_hourly_stats (hour, dimension, dim_value, count) VALUES (?, ?, ?, ?)
			 ON CONFLICT(hour, dimension, dim_value) DO UPDATE SET count = count + excluded.count`,
			rec.Hour, rec.Dimension, rec.DimValue, rec.Count,
		).Error
		if err != nil {
			logger.Warnf("[EgressLog] SnapshotHour upsert failed (%s/%s/%s): %v", rec.Hour, rec.Dimension, rec.DimValue, err)
		}
	}

	for _, ipCount := range topIPs {
		err := ss.db.Exec(
			`INSERT INTO egresslog_top_ips (hour, ip, count) VALUES (?, ?, ?)
			 ON CONFLICT(hour, ip) DO UPDATE SET count = count + excluded.count`,
			hour, ipCount.IP, ipCount.Count,
		).Error
		if err != nil {
			logger.Warnf("[EgressLog] SnapshotTopIP upsert failed (%s/%s): %v", hour, ipCount.IP, err)
		}
	}
}

// GetAggregatedStats 从数据库聚合指定时间范围内的统计
func (ss *StatsStore) GetAggregatedStats(retentionDays int) Stats {
	if ss.db == nil {
		return Stats{}
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02T15")

	stats := Stats{
		ByDstIP: make(map[string]int),
	}

	var totalResult struct{ Total int64 }
	ss.db.Model(&models.EgresslogHourlyStat{}).
		Select("COALESCE(SUM(count), 0) as total").
		Where("dimension = ? AND hour >= ?", "total", cutoff).
		Scan(&totalResult)
	stats.TotalDropped = int(totalResult.Total)

	var ipResults []models.EgresslogHourlyStat
	ss.db.Select("dim_value, SUM(count) as count").
		Where("dimension = ? AND hour >= ?", "dst_ip", cutoff).
		Group("dim_value").
		Order("count DESC").
		Limit(20).
		Find(&ipResults)
	for _, r := range ipResults {
		stats.ByDstIP[r.DimValue] = int(r.Count)
	}

	return stats
}

// GetHourlyTrend 获取最近 N 小时的趋势数据
func (ss *StatsStore) GetHourlyTrend(hours int) []HourlyTrendItem {
	if ss.db == nil {
		return nil
	}
	now := time.Now()
	currentHourKey := now.Format("2006-01-02T15")
	startHour := now.Add(-time.Duration(hours-1) * time.Hour).Format("2006-01-02T15")

	hourMap := make(map[string]*HourlyTrendItem, hours)

	var statItems []models.EgresslogHourlyStat
	err := ss.db.Select("hour, dim_value, SUM(count) as count").
		Where("hour >= ? AND hour < ? AND dimension = ?", startHour, currentHourKey, "dst_ip").
		Group("hour, dim_value").
		Find(&statItems).Error
	if err != nil {
		logger.Warnf("[EgressLog] query trend from hourly_stats failed: %v", err)
	}
	for _, row := range statItems {
		if _, ok := hourMap[row.Hour]; !ok {
			hourMap[row.Hour] = &HourlyTrendItem{Hour: row.Hour, Breakdown: make(map[string]int64)}
		}
		hourMap[row.Hour].Breakdown[row.DimValue] = row.Count
		hourMap[row.Hour].Total += row.Count
	}

	tableName := "egresslog_" + now.Format("20060102")
	currentHour := now.Hour()
	var liveItems []struct {
		DstIP string `json:"dst_ip"`
		Count int64  `json:"count"`
	}
	err = ss.db.Table(tableName).
		Select("dst_ip, COUNT(*) as count").
		Where("hour = ?", currentHour).
		Group("dst_ip").
		Find(&liveItems).Error
	if err != nil {
		hourMap[currentHourKey] = &HourlyTrendItem{Hour: currentHourKey, Total: 0, Breakdown: make(map[string]int64)}
	} else {
		item := &HourlyTrendItem{Hour: currentHourKey, Breakdown: make(map[string]int64)}
		for _, row := range liveItems {
			item.Breakdown[row.DstIP] = row.Count
			item.Total += row.Count
		}
		hourMap[currentHourKey] = item
	}

	result := make([]HourlyTrendItem, 0, hours)
	for i := hours - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		hourKey := t.Format("2006-01-02T15")
		if item, ok := hourMap[hourKey]; ok {
			result = append(result, *item)
		} else {
			result = append(result, HourlyTrendItem{Hour: hourKey, Total: 0, Breakdown: make(map[string]int64)})
		}
	}

	return result
}

// GetTopIPs 从 egresslog_top_ips 表查询时间范围内 Top N IP
func (ss *StatsStore) GetTopIPs(retentionDays int, limit int) []IPCount {
	if ss.db == nil {
		return nil
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02T15")

	var results []struct {
		IP    string `json:"ip"`
		Total int64  `json:"total"`
	}
	ss.db.Model(&models.EgresslogTopIP{}).
		Select("ip, SUM(count) as total").
		Where("hour >= ?", cutoff).
		Group("ip").
		Order("total DESC").
		Limit(limit).
		Scan(&results)

	ips := make([]IPCount, len(results))
	for i, r := range results {
		ips[i] = IPCount{IP: r.IP, Count: int(r.Total)}
	}
	return ips
}

// CleanupOldHourlyData 清理 N 天前的 egresslog_hourly_stats 和 egresslog_top_ips 数据
func (ss *StatsStore) CleanupOldHourlyData(retainDays int) error {
	if ss.db == nil {
		return nil
	}
	cutoffTime := time.Now().AddDate(0, 0, -retainDays).Format("2006-01-02T15")

	result := ss.db.Where("hour < ?", cutoffTime).Delete(&models.EgresslogHourlyStat{})
	if result.Error != nil {
		return result.Error
	}
	deleted := result.RowsAffected

	result = ss.db.Where("hour < ?", cutoffTime).Delete(&models.EgresslogTopIP{})
	if result.Error != nil {
		return result.Error
	}
	deleted += result.RowsAffected

	logger.Infof("[EgressLog] Cleaned up %d hourly stats rows older than %d days", deleted, retainDays)
	return nil
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
