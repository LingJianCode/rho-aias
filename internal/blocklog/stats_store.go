package blocklog

import (
	"time"

	"rho-aias/internal/logger"
	"rho-aias/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// StatsStore 基于业务数据库 (GORM) 的阻断统计持久化存储
type StatsStore struct {
	db *gorm.DB
}

// HourlyTrendItem 单小时趋势数据
type HourlyTrendItem struct {
	Hour       string         `json:"hour"`        // 格式: "2026-04-10T14"
	Total      int64          `json:"total"`       // 该小时总计数
	Breakdown map[string]int64 `json:"breakdown"` // 按规则来源细分
}

// DroppedSummary 丢弃概要
type DroppedSummary struct {
	Total   int64             `json:"total"`   // 总丢弃数
	Sources map[string]int64  `json:"sources"` // 按来源统计
	Hourly  []HourlyTrendItem `json:"hourly"`  // 小时趋势
}

// NewStatsStore 创建统计存储实例（接收外部注入的 *gorm.DB）
func NewStatsStore(db *gorm.DB) *StatsStore {
	return &StatsStore{db: db}
}

// Record 记录一条阻断事件到数据库
// 热路径调用，使用 db.Exec 原生 UPSERT 避免 GORM callback 开销；失败仅 warn 不阻塞主流程
func (ss *StatsStore) Record(ruleSource string) {
	if ss.db == nil {
		return
	}
	hourKey := time.Now().Format("2006-01-02T15")

	err := ss.db.Exec(
		`INSERT INTO hourly_stats (hour, rule_source, count) VALUES (?, ?, 1)
		 ON CONFLICT(hour, rule_source) DO UPDATE SET count = count + 1`,
		hourKey, ruleSource,
	).Error
	if err != nil {
		logger.Warnf("[StatsStore] Record failed: %v", err)
	}
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

		var items []models.HourlyStat
		err := ss.db.Select("rule_source, SUM(count) as count").
			Where("hour = ?", hourKey).
			Group("rule_source").
			Find(&items).Error
		if err != nil {
			logger.Warnf("[StatsStore] query trend failed for %s: %v", hourKey, err)
			result = append(result, HourlyTrendItem{Hour: hourKey, Total: 0, Breakdown: make(map[string]int64)})
			continue
		}

		item := HourlyTrendItem{Hour: hourKey, Breakdown: make(map[string]int64)}
		for _, row := range items {
			item.Total += row.Count
			item.Breakdown[row.RuleSource] = row.Count
		}

		result = append(result, item)
	}

	return result
}

// GetDroppedSummary 获取丢弃概览
func (ss *StatsStore) GetDroppedSummary(hours int) DroppedSummary {
	trend := ss.GetHourlyTrend(hours)

	sources := make(map[string]int64)
	var total int64
	for _, item := range trend {
		total += item.Total
		for src, cnt := range item.Breakdown {
			sources[src] += cnt
		}
	}

	return DroppedSummary{
		Total:   total,
		Sources: sources,
		Hourly:  trend,
	}
}

// Cleanup 清理 N 天前的历史数据
func (ss *StatsStore) Cleanup(retainDays int) error {
	if ss.db == nil {
		return nil
	}
	cutoffTime := time.Now().AddDate(0, 0, -retainDays).Format("2006-01-02T15")
	result := ss.db.Where("hour < ?", cutoffTime).Delete(&models.HourlyStat{})
	if result.Error != nil {
		return result.Error
	}
	logger.Infof("[StatsStore] Cleaned up %d rows older than %s days", result.RowsAffected, retainDays)
	return nil
}

// UpsertRecord 使用 GORM clause.OnConflict 做 upsert（备选 API，性能略低于 Exec 但更规范）
func (ss *StatsStore) UpsertRecord(ruleSource string) error {
	if ss.db == nil {
		return nil
	}
	hourKey := time.Now().Format("2006-01-02T15")
	return ss.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "hour"}, {Name: "rule_source"}},
		DoUpdates: clause.AssignmentColumns([]string{"count"}),
	}).Create(&models.HourlyStat{
		Hour:       hourKey,
		RuleSource: ruleSource,
		Count:      1,
	}).Error
}
