package blocklog

import (
	"fmt"
	"strings"
	"time"

	"rho-aias/internal/logger"
	"rho-aias/internal/models"

	"gorm.io/gorm"
)

// StatsStore 基于业务数据库 (GORM) 的阻断统计持久化存储
type StatsStore struct {
	db *gorm.DB
}

// HourlyTrendItem 单小时趋势数据
type HourlyTrendItem struct {
	Hour      string           `json:"hour"`      // 格式: "2026-04-10T14"
	Total     int64            `json:"total"`     // 该小时总计数
	Breakdown map[string]int64 `json:"breakdown"` // 按规则来源细分
}

// NewStatsStore 创建统计存储实例（接收外部注入的 *gorm.DB）
func NewStatsStore(db *gorm.DB) *StatsStore {
	return &StatsStore{db: db}
}

// SnapshotHour 将指定小时的统计快照写入数据库（整点轮转时调用）
func (ss *StatsStore) SnapshotHour(hour string, stats Stats, topIPs []IPCount) {
	if ss.db == nil {
		return
	}

	// 批量写入 blocklog_hourly_stats
	records := []models.BlocklogHourlyStat{}

	// total 维度
	records = append(records, models.BlocklogHourlyStat{
		Hour:      hour,
		Dimension: "total",
		DimValue:  "",
		Count:     int64(stats.TotalBlocked),
	})

	// rule_source 维度
	for src, cnt := range stats.ByRuleSource {
		records = append(records, models.BlocklogHourlyStat{
			Hour:      hour,
			Dimension: "rule_source",
			DimValue:  src,
			Count:     int64(cnt),
		})
	}

	// 批量 UPSERT
	for _, rec := range records {
		err := ss.db.Exec(
			`INSERT INTO blocklog_hourly_stats (hour, dimension, dim_value, count) VALUES (?, ?, ?, ?)
			 ON CONFLICT(hour, dimension, dim_value) DO UPDATE SET count = count + excluded.count`,
			rec.Hour, rec.Dimension, rec.DimValue, rec.Count,
		).Error
		if err != nil {
			logger.Warnf("[StatsStore] SnapshotHour upsert failed (%s/%s/%s): %v", rec.Hour, rec.Dimension, rec.DimValue, err)
		}
	}

	// 写入 TopIPs
	for _, ipCount := range topIPs {
		err := ss.db.Exec(
			`INSERT INTO blocklog_top_ips (hour, ip, count) VALUES (?, ?, ?)
			 ON CONFLICT(hour, ip) DO UPDATE SET count = count + excluded.count`,
			hour, ipCount.IP, ipCount.Count,
		).Error
		if err != nil {
			logger.Warnf("[StatsStore] SnapshotTopIP upsert failed (%s/%s): %v", hour, ipCount.IP, err)
		}
	}
}

// GetAggregatedStats 从数据库聚合指定时间范围内的统计（DB 历史数据）
func (ss *StatsStore) GetAggregatedStats(retentionDays int) Stats {
	if ss.db == nil {
		return Stats{}
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02T15")

	stats := Stats{
		ByRuleSource: make(map[string]int),
	}

	// Total
	var totalResult struct{ Total int64 }
	ss.db.Model(&models.BlocklogHourlyStat{}).
		Select("COALESCE(SUM(count), 0) as total").
		Where("dimension = ? AND hour >= ?", "total", cutoff).
		Scan(&totalResult)
	stats.TotalBlocked = int(totalResult.Total)

	// ByRuleSource
	var sourceResults []models.BlocklogHourlyStat
	ss.db.Select("dim_value, SUM(count) as count").
		Where("dimension = ? AND hour >= ?", "rule_source", cutoff).
		Group("dim_value").
		Find(&sourceResults)
	for _, r := range sourceResults {
		stats.ByRuleSource[r.DimValue] = int(r.Count)
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

	// 构建 hour -> HourlyTrendItem 的映射
	hourMap := make(map[string]*HourlyTrendItem, hours)

	// ---- 1. 从 blocklog_hourly_stats 批量查询历史小时数据（当前小时之前） ----
	var statItems []models.BlocklogHourlyStat
	err := ss.db.Select("hour, dim_value, SUM(count) as count").
		Where("hour >= ? AND hour < ? AND dimension = ?", startHour, currentHourKey, "rule_source").
		Group("hour, dim_value").
		Find(&statItems).Error
	if err != nil {
		logger.Warnf("[StatsStore] query trend from hourly_stats failed: %v", err)
	}
	for _, row := range statItems {
		if _, ok := hourMap[row.Hour]; !ok {
			hourMap[row.Hour] = &HourlyTrendItem{Hour: row.Hour, Breakdown: make(map[string]int64)}
		}
		hourMap[row.Hour].Breakdown[row.DimValue] = row.Count
		hourMap[row.Hour].Total += row.Count
	}

	// ---- 2. 从当天 BlocklogRecord 分表实时聚合当前小时数据 ----
	tableName := "blocklog_" + now.Format("20060102")
	currentHour := now.Hour()
	var liveItems []struct {
		RuleSource string `json:"rule_source"`
		Count      int64  `json:"count"`
	}
	err = ss.db.Table(tableName).
		Select("rule_source, COUNT(*) as count").
		Where("hour = ?", currentHour).
		Group("rule_source").
		Find(&liveItems).Error
	if err != nil {
		logger.Warnf("[StatsStore] query live trend from %s failed: %v", tableName, err)
		// 当前小时无数据时填零
		hourMap[currentHourKey] = &HourlyTrendItem{Hour: currentHourKey, Total: 0, Breakdown: make(map[string]int64)}
	} else {
		item := &HourlyTrendItem{Hour: currentHourKey, Breakdown: make(map[string]int64)}
		for _, row := range liveItems {
			item.Breakdown[row.RuleSource] = row.Count
			item.Total += row.Count
		}
		hourMap[currentHourKey] = item
	}

	// ---- 3. 按时间顺序组装结果，缺失的小时填零 ----
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

// GetTopIPs 从 blocklog_top_ips 表查询时间范围内 Top N IP
func (ss *StatsStore) GetTopIPs(retentionDays int, limit int) []IPCount {
	if ss.db == nil {
		return nil
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02T15")

	var results []struct {
		IP    string `json:"ip"`
		Total int64  `json:"total"`
	}
	ss.db.Model(&models.BlocklogTopIP{}).
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

// CleanupOldHourlyData 清理 N 天前的 blocklog_hourly_stats 和 blocklog_top_ips 数据
func (ss *StatsStore) CleanupOldHourlyData(retainDays int) error {
	if ss.db == nil {
		return nil
	}
	cutoffTime := time.Now().AddDate(0, 0, -retainDays).Format("2006-01-02T15")

	result := ss.db.Where("hour < ?", cutoffTime).Delete(&models.BlocklogHourlyStat{})
	if result.Error != nil {
		return result.Error
	}
	deleted := result.RowsAffected

	result = ss.db.Where("hour < ?", cutoffTime).Delete(&models.BlocklogTopIP{})
	if result.Error != nil {
		return result.Error
	}
	deleted += result.RowsAffected

	logger.Infof("[StatsStore] Cleaned up %d hourly stats rows older than %d days", deleted, retainDays)
	return nil
}

// QueryRecords 从按天分表查询阻断记录（支持跨小时范围查询）
func (ss *StatsStore) QueryRecords(filter RecordFilter) (*PageResult, error) {
	if ss.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// 验证 date 格式
	parsedDate, err := time.Parse("2006-01-02", filter.Date)
	if err != nil {
		return nil, fmt.Errorf("invalid date format, expected YYYY-MM-DD, got: %s", filter.Date)
	}

	tableName := "blocklog_" + parsedDate.Format("20060102")

	// 检查表是否存在
	if !ss.db.Migrator().HasTable(tableName) {
		return &PageResult{
			Records:  []BlockRecord{},
			Total:    0,
			Page:     filter.Page,
			PageSize: filter.PageSize,
		}, nil
	}

	// 设置默认分页参数
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

	// 设置默认小时范围
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

	// 构建查询
	query := ss.db.Table(tableName).Where("hour BETWEEN ? AND ?", startHour, endHour)

	if filter.MatchType != "" {
		query = query.Where("match_type = ?", filter.MatchType)
	}
	if filter.RuleSource != "" {
		query = query.Where("rule_source = ?", filter.RuleSource)
	}
	if filter.SrcIP != "" {
		query = query.Where("src_ip = ?", filter.SrcIP)
	}
	if filter.CountryCode != "" {
		query = query.Where("country_code = ?", filter.CountryCode)
	}

	// COUNT
	var total int64
	query.Count(&total)

	// 分页查询（按 id DASC）
	var rows []models.BlocklogRecord
	offset := (page - 1) * pageSize
	if err := query.Order("id DASC").Offset(offset).Limit(pageSize).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("query records failed: %w", err)
	}

	// 转换为 BlockRecord
	records := make([]BlockRecord, len(rows))
	for i, r := range rows {
		records[i] = BlockRecord{
			Timestamp:   r.Timestamp,
			SrcIP:       r.SrcIP,
			DstIP:       r.DstIP,
			DstPort:     r.DstPort,
			MatchType:   r.MatchType,
			RuleSource:  r.RuleSource,
			CountryCode: r.CountryCode,
			PacketSize:  r.PacketSize,
		}
	}

	return &PageResult{
		Records:  records,
		Total:    int(total),
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// AggregateTopIPsFromTable 从按天分表聚合 Top IP（替代从 JSONL 文件聚合）
func (ss *StatsStore) AggregateTopIPsFromTable(hourKey string) []IPCount {
	if ss.db == nil {
		return nil
	}

	// hourKey 格式: "2026-04-17T14"
	parts := strings.SplitN(hourKey, "T", 2)
	if len(parts) != 2 {
		return nil
	}

	dateStr := parts[0] // "2026-04-17"
	hourStr := parts[1] // "14"

	parsedDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return nil
	}

	tableName := "blocklog_" + parsedDate.Format("20060102")
	if !ss.db.Migrator().HasTable(tableName) {
		return nil
	}

	var hour int
	fmt.Sscanf(hourStr, "%d", &hour)

	var results []struct {
		SrcIP string `json:"src_ip"`
		Count int64  `json:"count"`
	}

	ss.db.Table(tableName).
		Select("src_ip, COUNT(*) as count").
		Where("hour = ?", hour).
		Group("src_ip").
		Having("COUNT(*) > 1").
		Order("count DESC").
		Find(&results)

	if len(results) == 0 {
		return nil
	}

	ips := make([]IPCount, len(results))
	for i, r := range results {
		ips[i] = IPCount{IP: r.SrcIP, Count: int(r.Count)}
	}
	return ips
}

// AggregateStatsFromTable 从按天分表 SQL 聚合指定小时的统计数据
// hourKey 格式: "2026-04-17T14"
func (ss *StatsStore) AggregateStatsFromTable(hourKey string) Stats {
	if ss.db == nil {
		return Stats{}
	}

	// hourKey 格式: "2026-04-17T14"
	parts := strings.SplitN(hourKey, "T", 2)
	if len(parts) != 2 {
		return Stats{}
	}

	dateStr := parts[0] // "2026-04-17"
	hourStr := parts[1] // "14"

	parsedDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return Stats{}
	}

	tableName := "blocklog_" + parsedDate.Format("20060102")
	if !ss.db.Migrator().HasTable(tableName) {
		return Stats{}
	}

	var hour int
	fmt.Sscanf(hourStr, "%d", &hour)

	stats := Stats{
		ByRuleSource: make(map[string]int),
	}

	// 按 rule_source 聚合
	var results []struct {
		RuleSource string `json:"rule_source"`
		Count      int64  `json:"count"`
	}

	ss.db.Table(tableName).
		Select("rule_source, COUNT(*) as count").
		Where("hour = ?", hour).
		Group("rule_source").
		Find(&results)

	for _, r := range results {
		stats.ByRuleSource[r.RuleSource] = int(r.Count)
		stats.TotalBlocked += int(r.Count)
	}

	return stats
}

// CleanupOldDayTables 清理 N 天前的按天分表（DROP TABLE）
func (ss *StatsStore) CleanupOldDayTables(retainDays int) error {
	if ss.db == nil {
		return nil
	}

	cutoffDate := time.Now().AddDate(0, 0, -retainDays)

	// 查询所有 blocklog_ 开头的表
	var tableNames []string
	if err := ss.db.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'blocklog_2%'").Scan(&tableNames).Error; err != nil {
		return fmt.Errorf("query sqlite_master failed: %w", err)
	}

	dropped := 0
	for _, name := range tableNames {
		// 提取日期部分：blocklog_20260417 -> 20260417
		dateStr := strings.TrimPrefix(name, "blocklog_")
		if len(dateStr) != 8 {
			continue
		}

		parsed, err := time.Parse("20060102", dateStr)
		if err != nil {
			continue
		}

		if parsed.Before(cutoffDate) {
			if err := ss.db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", name)).Error; err != nil {
				logger.Warnf("[StatsStore] Failed to drop table %s: %v", name, err)
			} else {
				dropped++
				logger.Infof("[StatsStore] Dropped old daily table: %s", name)
			}
		}
	}

	logger.Infof("[StatsStore] Cleaned up %d daily tables older than %d days", dropped, retainDays)
	return nil
}

// TableExists 检查指定表是否存在
func (ss *StatsStore) TableExists(tableName string) bool {
	if ss.db == nil {
		return false
	}
	return ss.db.Migrator().HasTable(tableName)
}

// QueryEmptyCountryRecords 查询指定分表中 country_code 为空的记录（按 src_ip 去重）
// 返回 map[srcIP] => []recordID，限制去重后的 IP 数量不超过 batchSize
func (ss *StatsStore) QueryEmptyCountryRecords(tableName string, batchSize int) (map[string][]uint, error) {
	if ss.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// 查询 country_code 为空的记录，按 src_ip 分组，限制 IP 数量
	type ipGroup struct {
		SrcIP string `json:"src_ip"`
	}
	var groups []ipGroup
	if err := ss.db.Table(tableName).
		Select("DISTINCT src_ip").
		Where("country_code = '' OR country_code IS NULL").
		Limit(batchSize).
		Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("query distinct src_ip failed: %w", err)
	}

	if len(groups) == 0 {
		return nil, nil
	}

	// 收集所有 IP
	ipSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		ipSet[g.SrcIP] = struct{}{}
	}

	// 查询这些 IP 对应的记录 ID
	type idIP struct {
		ID    uint   `json:"id"`
		SrcIP string `json:"src_ip"`
	}
	var idIPs []idIP
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	if err := ss.db.Table(tableName).
		Select("id, src_ip").
		Where("country_code = '' OR country_code IS NULL").
		Where("src_ip IN ?", ips).
		Find(&idIPs).Error; err != nil {
		return nil, fmt.Errorf("query record ids failed: %w", err)
	}

	result := make(map[string][]uint)
	for _, item := range idIPs {
		result[item.SrcIP] = append(result[item.SrcIP], item.ID)
	}

	return result, nil
}

// BatchUpdateCountryCode 批量更新记录的 country_code
func (ss *StatsStore) BatchUpdateCountryCode(tableName string, updates map[uint]string) error {
	if ss.db == nil || len(updates) == 0 {
		return nil
	}

	return ss.db.Transaction(func(tx *gorm.DB) error {
		for id, countryCode := range updates {
			if err := tx.Table(tableName).
				Where("id = ?", id).
				Update("country_code", countryCode).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
