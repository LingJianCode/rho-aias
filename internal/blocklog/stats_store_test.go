package blocklog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) *StatsStore {
	t.Helper()
	dir := t.TempDir()
	ss, err := NewStatsStore(dir)
	if err != nil {
		t.Fatalf("NewStatsStore failed: %v", err)
	}
	return ss
}

func TestRecord_Increment(t *testing.T) {
	ss := setupTestDB(t)
	defer ss.Close()

	// 写入同一小时、同一来源的 3 条记录
	for i := 0; i < 3; i++ {
		ss.Record("ipsum")
	}

	hourKey := time.Now().Format("2006-01-02T15")
	var count int64
	err := ss.db.QueryRow(
		`SELECT count FROM hourly_stats WHERE hour = ? AND rule_source = ?`,
		hourKey, "ipsum",
	).Scan(&count)

	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected count=3, got %d", count)
	}
}

func TestRecord_MultipleSources(t *testing.T) {
	ss := setupTestDB(t)
	defer ss.Close()

	ss.Record("ipsum")
	ss.Record("spamhaus")
	ss.Record("ipsum")

	hourKey := time.Now().Format("2006-01-02T15")

	var ipsumCount int64
	if err := ss.db.QueryRow(
		`SELECT count FROM hourly_stats WHERE hour = ? AND rule_source = ?`,
		hourKey, "ipsum",
	).Scan(&ipsumCount); err != nil {
		t.Fatalf("failed to query ipsum count: %v", err)
	}

	var spamhausCount int64
	if err := ss.db.QueryRow(
		`SELECT count FROM hourly_stats WHERE hour = ? AND rule_source = ?`,
		hourKey, "spamhaus",
	).Scan(&spamhausCount); err != nil {
		t.Fatalf("failed to query spamhaus count: %v", err)
	}

	if ipsumCount != 2 {
		t.Errorf("expected ipsum=2, got %d", ipsumCount)
	}
	if spamhausCount != 1 {
		t.Errorf("expected spamhaus=1, got %d", spamhausCount)
	}
}

func TestGetHourlyTrend_Basic(t *testing.T) {
	ss := setupTestDB(t)
	defer ss.Close()

	ss.Record("manual")
	ss.Record("geo")

	trend := ss.GetHourlyTrend(24)

	if len(trend) != 24 {
		t.Errorf("expected 24 hours, got %d", len(trend))
	}

	// 当前小时应有数据
	currentHourKey := time.Now().Format("2006-01-02T15")
	foundCurrentHour := false
	for _, item := range trend {
		if item.Hour == currentHourKey && item.Total == 2 {
			foundCurrentHour = true
			break
		}
	}
	if !foundCurrentHour {
		t.Errorf("current hour not found or total mismatch in trend data")
	}
}

func TestGetHourlyTrend_ZeroFill(t *testing.T) {
	ss := setupTestDB(t)
	defer ss.Close()

	trend := ss.GetHourlyTrend(48)

	if len(trend) != 48 {
		t.Errorf("expected 48 hours, got %d", len(trend))
	}

	// 大部分小时应该是零（除了当前小时）
	zeroHours := 0
	for _, item := range trend {
		if item.Total == 0 {
			zeroHours++
		}
	}
	if zeroHours < 47 { // 至少 47 个小时应该为 0
		t.Errorf("expected at least 47 zero-fill hours, got %d", zeroHours)
	}
}

func TestCleanup_OldData(t *testing.T) {
	ss := setupTestDB(t)
	defer ss.Close()

	// 插入当前小时数据
	ss.Record("test")

	// 手动插入一条旧数据（30天前）
	oldHour := time.Now().AddDate(0, 0, -30).Format("2006-01-02T15")
	if _, err := ss.db.Exec(
		`INSERT INTO hourly_stats (hour, rule_source, count) VALUES (?, ?, 100)`,
		oldHour, "old_source",
	); err != nil {
		t.Fatalf("failed to insert old data: %v", err)
	}

	// 清理 7 天前的数据
	if err := ss.Cleanup(7); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// 旧数据应被删除
	var oldCount int64
	err := ss.db.QueryRow(
		`SELECT COALESCE(SUM(count), 0) FROM hourly_stats WHERE hour < ?`,
		time.Now().AddDate(0, 0, -7).Format("2006-01-02T15"),
	).Scan(&oldCount)

	if err != nil {
		t.Fatalf("query after cleanup failed: %v", err)
	}
	if oldCount != 0 {
		t.Errorf("expected old data cleaned up, but got count=%d", oldCount)
	}

	// 当前数据应保留
	var currentCount int64
	currentHourKey := time.Now().Format("2006-01-02T15")
	if err := ss.db.QueryRow(`SELECT COALESCE(SUM(count), 0) FROM hourly_stats WHERE hour = ?`, currentHourKey).Scan(&currentCount); err != nil {
		t.Fatalf("failed to query current count: %v", err)
	}
	if currentCount == 0 {
		t.Error("current data should be preserved after cleanup")
	}
}

func TestReopen_PersistedData(t *testing.T) {
	dir := t.TempDir()

	// 第一阶段：写入数据后关闭
	ss1, err := NewStatsStore(dir)
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	ss1.Record("persisted_test")
	ss1.Close()

	// 第二阶段：重新打开，数据应存在
	ss2, err := NewStatsStore(dir)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer ss2.Close()

	trend := ss2.GetHourlyTrend(1)
	currentHourKey := time.Now().Format("2006-01-02T15")
	found := false
	for _, item := range trend {
		if item.Hour == currentHourKey && item.Total > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("data should persist across reopen")
	}
}

// 验证数据库文件确实创建
func TestDatabaseFileCreated(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "blocklog_stats.db")

	ss, _ := NewStatsStore(dir)
	ss.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("database file should exist")
	}

	walPath := dbPath + "-wal"
	if _, err := os.Stat(walPath); os.IsNotExist(err) {
		t.Log("WAL file may not exist yet if no writes occurred (acceptable)")
	}
}
