package blocklog

import (
	"sort"
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
	Hour       string           `json:"hour"`        // 格式: "2026-04-10T14"
	Total      int64            `json:"total"`       // 该小时总计数
	Breakdown  map[string]int64 `json:"breakdown"`   // 按规则来源细分
}

// NewStatsStore 创建统计存储实例（接收外部注入的 *gorm.DB）
func NewStatsStore(db *gorm.DB) *StatsStore {
	return &StatsStore{db: db}
}

// SnapshotHour 将指定小时的统计快照写入数据库（整点轮转时调用）
func (ss *StatsStore) SnapshotHour(hour string, stats Stats) {
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

	// country 维度
	for country, cnt := range stats.ByCountry {
		records = append(records, models.BlocklogHourlyStat{
			Hour:      hour,
			Dimension: "country",
			DimValue:  country,
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

	// 写入 TopIPs（count > 10 才写入）
	for _, ipCount := range stats.TopBlockedIPs {
		if ipCount.Count <= 10 {
			continue
		}
		err := ss.db.Exec(
			`INSERT INTO blocklog_top_ips (ip, count) VALUES (?, ?)
			 ON CONFLICT(ip) DO UPDATE SET count = count + excluded.count`,
			ipCount.IP, ipCount.Count,
		).Error
		if err != nil {
			logger.Warnf("[StatsStore] SnapshotTopIP upsert failed (%s): %v", ipCount.IP, err)
		}
	}
}

// GetAggregatedStats 从数据库聚合全量统计（纯 DB 查询）
func (ss *StatsStore) GetAggregatedStats() Stats {
	if ss.db == nil {
		return Stats{}
	}

	stats := Stats{
		ByRuleSource:        make(map[string]int),
		ByCountry:           make(map[string]int),
		TopBlockedIPs:       []IPCount{},
		TopBlockedCountries: []CountryCount{},
	}

	// Total
	var totalResult struct{ Total int64 }
	ss.db.Model(&models.BlocklogHourlyStat{}).
		Select("COALESCE(SUM(count), 0) as total").
		Where("dimension = ?", "total").
		Scan(&totalResult)
	stats.TotalBlocked = int(totalResult.Total)

	// ByRuleSource
	var sourceResults []models.BlocklogHourlyStat
	ss.db.Select("dim_value, SUM(count) as count").
		Where("dimension = ?", "rule_source").
		Group("dim_value").
		Find(&sourceResults)
	for _, r := range sourceResults {
		stats.ByRuleSource[r.DimValue] = int(r.Count)
	}

	// ByCountry
	var countryResults []models.BlocklogHourlyStat
	ss.db.Select("dim_value, SUM(count) as count").
		Where("dimension = ?", "country").
		Group("dim_value").
		Find(&countryResults)
	for _, r := range countryResults {
		stats.ByCountry[r.DimValue] = int(r.Count)
	}

	// TopBlockedIPs (from blocklog_top_ips)
	var topIPResults []models.BlocklogTopIP
	ss.db.Order("count DESC").Limit(10).Find(&topIPResults)
	for _, r := range topIPResults {
		stats.TopBlockedIPs = append(stats.TopBlockedIPs, IPCount{IP: r.IP, Count: int(r.Count)})
	}

	// TopBlockedCountries (从 ByCountry 排序取 Top10)
	type cn struct {
		Country string
		Count   int
	}
	var countries []cn
	for country, count := range stats.ByCountry {
		countries = append(countries, cn{country, count})
	}
	sort.Slice(countries, func(i, j int) bool { return countries[i].Count > countries[j].Count })
	if len(countries) > 10 {
		countries = countries[:10]
	}
	stats.TopBlockedCountries = make([]CountryCount, len(countries))
	for i, c := range countries {
		stats.TopBlockedCountries[i] = CountryCount{Country: c.Country, Count: c.Count}
	}

	return stats
}

// GetHourlyTrend 获取最近 N 小时的趋势数据
func (ss *StatsStore) GetHourlyTrend(hours int) []HourlyTrendItem {
	if ss.db == nil {
		return nil
	}
	now := time.Now()
	result := make([]HourlyTrendItem, 0, hours)

	for i := hours - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		hourKey := t.Format("2006-01-02T15")

		var items []models.BlocklogHourlyStat
		err := ss.db.Select("dim_value, SUM(count) as count").
			Where("hour = ? AND dimension = ?", hourKey, "rule_source").
			Group("dim_value").
			Find(&items).Error
		if err != nil {
			logger.Warnf("[StatsStore] query trend failed for %s: %v", hourKey, err)
			result = append(result, HourlyTrendItem{Hour: hourKey, Total: 0, Breakdown: make(map[string]int64)})
			continue
		}

		item := HourlyTrendItem{Hour: hourKey, Breakdown: make(map[string]int64)}
		for _, row := range items {
			item.Total += row.Count
			item.Breakdown[row.DimValue] = row.Count
		}

		result = append(result, item)
	}

	return result
}

// GetTopIPs 从 blocklog_top_ips 表直接查询 Top N IP
func (ss *StatsStore) GetTopIPs(limit int) ([]IPCount, int64) {
	if ss.db == nil {
		return nil, 0
	}

	var total int64
	ss.db.Model(&models.BlocklogTopIP{}).Count(&total)

	var results []models.BlocklogTopIP
	ss.db.Order("count DESC").Limit(limit).Find(&results)

	ips := make([]IPCount, len(results))
	for i, r := range results {
		ips[i] = IPCount{IP: r.IP, Count: int(r.Count)}
	}
	return ips, total
}

// GetTopCountries 从 blocklog_hourly_stats 聚合查询 Top N 国家
func (ss *StatsStore) GetTopCountries(limit int) ([]CountryCount, int) {
	if ss.db == nil {
		return nil, 0
	}

	var results []models.BlocklogHourlyStat
	ss.db.Select("dim_value, SUM(count) as count").
		Where("dimension = ?", "country").
		Group("dim_value").
		Order("count DESC").
		Limit(limit).
		Find(&results)

	// 总国家数
	var totalCountries []models.BlocklogHourlyStat
	ss.db.Select("DISTINCT dim_value").
		Where("dimension = ?", "country").
		Find(&totalCountries)

	countries := make([]CountryCount, len(results))
	for i, r := range results {
		countries[i] = CountryCount{Country: r.DimValue, Count: int(r.Count)}
	}
	return countries, len(totalCountries)
}

// Cleanup 清理 N 天前的历史数据
func (ss *StatsStore) Cleanup(retainDays int) error {
	if ss.db == nil {
		return nil
	}
	cutoffTime := time.Now().AddDate(0, 0, -retainDays).Format("2006-01-02T15")
	result := ss.db.Where("hour < ?", cutoffTime).Delete(&models.BlocklogHourlyStat{})
	if result.Error != nil {
		return result.Error
	}
	logger.Infof("[StatsStore] Cleaned up %d rows older than %s days", result.RowsAffected, retainDays)
	return nil
}
