package blocklog

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/glebarez/sqlite" // 纯 Go SQLite 驱动，无 CGO

	"rho-aias/internal/logger"
)

// StatsStore 基于 SQLite 的阻断统计持久化存储
type StatsStore struct {
	db *sql.DB
}

// HourlyTrendItem 单小时趋势数据
type HourlyTrendItem struct {
	Hour       string         `json:"hour"`        // 格式: "2026-04-10T14"
	Total      int64          `json:"total"`       // 该小时总计数
	Breakdown map[string]int64 `json:"breakdown"` // 按规则来源细分
}

// DroppedSummary 丢弃概要
type DroppedSummary struct {
	Total   int64                `json:"total"`    // 总丢弃数
	Sources map[string]int64     `json:"sources"`  // 按来源统计
	Hourly  []HourlyTrendItem    `json:"hourly"`   // 小时趋势
}

// NewStatsStore 创建统计存储实例
func NewStatsStore(dataDir string) (*StatsStore, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "blocklog_stats.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// 连接池配置（SQLite 单写多读场景）
	db.SetMaxOpenConns(1) // SQLite 写入需串行，避免 "database is locked"
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// 启用 WAL 模式，提升并发读写性能
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	ss := &StatsStore{db: db}

	if err := ss.initTable(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init table: %w", err)
	}

	return ss, nil
}

// initTable 初始化表结构
func (ss *StatsStore) initTable() error {
	_, err := ss.db.Exec(`
		CREATE TABLE IF NOT EXISTS hourly_stats (
			hour TEXT NOT NULL,
			rule_source TEXT NOT NULL DEFAULT '',
			count INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (hour, rule_source)
		);
		CREATE INDEX IF NOT EXISTS idx_hourly_stats_hour ON hourly_stats(hour);
	`)
	return err
}

// Record 记录一条阻断事件到 SQLite
// 热路径调用，失败仅 warn 不阻塞主流程
func (ss *StatsStore) Record(ruleSource string) {
	hourKey := time.Now().Format("2006-01-02T15")

	_, err := ss.db.Exec(
		`INSERT INTO hourly_stats (hour, rule_source, count) VALUES (?, ?, 1)
		 ON CONFLICT(hour, rule_source) DO UPDATE SET count = count + 1`,
		hourKey, ruleSource,
	)
	if err != nil {
		logger.Warnf("[StatsStore] Record failed: %v", err)
	}
}

// GetHourlyTrend 获取最近 N 小时的趋势数据
func (ss *StatsStore) GetHourlyTrend(hours int) []HourlyTrendItem {
	now := time.Now()
	result := make([]HourlyTrendItem, 0, hours)

	for i := hours - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		hourKey := t.Format("2006-01-02T15")

		rows, err := ss.db.Query(
			`SELECT COALESCE(SUM(count), 0), rule_source FROM hourly_stats WHERE hour = ? GROUP BY rule_source`,
			hourKey,
		)
		if err != nil {
			logger.Warnf("[StatsStore] query trend failed for %s: %v", hourKey, err)
			result = append(result, HourlyTrendItem{Hour: hourKey, Total: 0, Breakdown: make(map[string]int64)})
			continue
		}

		item := HourlyTrendItem{Hour: hourKey, Breakdown: make(map[string]int64)}
		for rows.Next() {
			var count int64
			var src string
			if err := rows.Scan(&count, &src); err == nil {
				item.Total += count
				item.Breakdown[src] = count
			}
		}
		rows.Close()

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
	cutoffTime := time.Now().AddDate(0, 0, -retainDays).Format("2006-01-02T15")
	result, err := ss.db.Exec(`DELETE FROM hourly_stats WHERE hour < ?`, cutoffTime)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	logger.Infof("[StatsStore] Cleaned up %d rows older than %s days", rowsAffected, retainDays)
	return nil
}

// Close 关闭数据库连接
func (ss *StatsStore) Close() error {
	if ss.db != nil {
		return ss.db.Close()
	}
	return nil
}
