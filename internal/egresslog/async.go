// Package egresslog Egress 丢包日志模块
package egresslog

import (
	"fmt"
	"sync"
	"time"

	"rho-aias/internal/logger"
	"rho-aias/internal/models"

	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

const (
	// defaultBatchSize 批量写入阈值
	defaultBatchSize = 100
)

// Config 持久化配置
type Config struct {
	BufferSize    int
	FlushInterval time.Duration
}

// AsyncWriter 异步日志写入器（写入 SQLite 按天分表）
type AsyncWriter struct {
	config     Config
	db         *gorm.DB
	statsStore *StatsStore
	recordCh   chan DropRecord
	stopCh     chan struct{}
	flushCh    chan chan struct{}
	wg         sync.WaitGroup
	stopped    bool
	stopMu     sync.RWMutex
	cron       *cron.Cron
}

// NewAsyncWriter 创建异步写入器
func NewAsyncWriter(config Config, db *gorm.DB, onRotate func(time.Time)) (*AsyncWriter, error) {
	aw := &AsyncWriter{
		config:   config,
		db:       db,
		recordCh: make(chan DropRecord, config.BufferSize),
		stopCh:   make(chan struct{}),
		flushCh:  make(chan chan struct{}, 1),
	}

	aw.cron = cron.New(cron.WithSeconds())

	flushExpr := "@every " + config.FlushInterval.String()
	if _, err := aw.cron.AddFunc(flushExpr, func() {
		aw.Flush()
	}); err != nil {
		return nil, fmt.Errorf("failed to add flush cron job: %w", err)
	}

	if onRotate != nil {
		if _, err := aw.cron.AddFunc("0 3 * * * *", func() {
			lastHour := time.Now().Add(-1 * time.Hour)
			onRotate(lastHour)
		}); err != nil {
			return nil, fmt.Errorf("failed to add rotate cron job: %w", err)
		}
	}

	if aw.statsStore != nil {
		if _, err := aw.cron.AddFunc("0 0 3 * * *", func() {
			if err := aw.statsStore.CleanupOldDayTables(defaultRetentionDays); err != nil {
				logger.Warnf("[EgressLog] Daily cleanup of old tables failed: %v", err)
			}
			if err := aw.statsStore.CleanupOldHourlyData(defaultRetentionDays); err != nil {
				logger.Warnf("[EgressLog] Daily cleanup of old hourly stats failed: %v", err)
			}
		}); err != nil {
			return nil, fmt.Errorf("failed to add cleanup cron job: %w", err)
		}
	}

	aw.cron.Start()

	aw.wg.Add(1)
	go aw.run()

	return aw, nil
}

// Write 异步写入一条记录
func (aw *AsyncWriter) Write(record DropRecord) error {
	aw.stopMu.RLock()
	stopped := aw.stopped
	aw.stopMu.RUnlock()

	if stopped {
		return nil
	}

	select {
	case aw.recordCh <- record:
	default:
		logger.Warnf("[EgressLog] Channel full (size=%d), dropping record: dstIP=%s, timestamp=%d",
			cap(aw.recordCh), record.DstIP, record.Timestamp)
	}

	return nil
}

// Stop 停止异步写入器
func (aw *AsyncWriter) Stop() error {
	aw.stopMu.Lock()
	if aw.stopped {
		aw.stopMu.Unlock()
		return nil
	}
	aw.stopped = true
	aw.stopMu.Unlock()

	if aw.cron != nil {
		aw.cron.Stop()
	}

	close(aw.stopCh)
	aw.wg.Wait()

	return nil
}

// Flush 手动刷新缓冲区
func (aw *AsyncWriter) Flush() error {
	aw.stopMu.RLock()
	stopped := aw.stopped
	aw.stopMu.RUnlock()

	if stopped {
		return nil
	}

	done := make(chan struct{})
	select {
	case aw.flushCh <- done:
		<-done
	default:
	}
	return nil
}

// run 后台写入协程
func (aw *AsyncWriter) run() {
	defer aw.wg.Done()

	var pendingRecords []DropRecord

	for {
		select {
		case record := <-aw.recordCh:
			pendingRecords = append(pendingRecords, record)
			if len(pendingRecords) >= defaultBatchSize {
				aw.writeBatch(pendingRecords)
				pendingRecords = pendingRecords[:0]
			}

		case done := <-aw.flushCh:
			if len(pendingRecords) > 0 {
				aw.writeBatch(pendingRecords)
				pendingRecords = pendingRecords[:0]
			}
			close(done)

		case <-aw.stopCh:
			if len(pendingRecords) > 0 {
				aw.writeBatch(pendingRecords)
			}
			return
		}
	}
}

// writeBatch 批量写入记录到 SQLite 按天分表
func (aw *AsyncWriter) writeBatch(records []DropRecord) {
	if aw.db == nil || len(records) == 0 {
		return
	}

	groups := make(map[string][]DropRecord)
	for _, r := range records {
		dayKey := dayKeyFromTimestamp(r.Timestamp)
		groups[dayKey] = append(groups[dayKey], r)
	}

	for dayKey, recs := range groups {
		tableName := "egresslog_" + dayKey

		if err := ensureDayTable(aw.db, tableName); err != nil {
			logger.Errorf("[EgressLog] Failed to ensure table %s: %v", tableName, err)
			continue
		}

		err := aw.db.Transaction(func(tx *gorm.DB) error {
			for _, r := range recs {
				row := models.EgresslogRecord{
					Hour:      hourFromTimestamp(r.Timestamp),
					Timestamp: r.Timestamp,
					DstIP:     r.DstIP,
					PktLen:    r.PktLen,
					Tokens:    r.Tokens,
					RateBytes: r.RateBytes,
				}
				if err := tx.Table(tableName).Create(&row).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			logger.Errorf("[EgressLog] Batch insert to %s failed (%d records): %v", tableName, len(recs), err)
		}
	}
}

// dayKeyFromTimestamp 从 Unix 纳秒时间戳提取日期键 "20060102"
func dayKeyFromTimestamp(ns int64) string {
	return time.Unix(0, ns).Format("20060102")
}

// hourFromTimestamp 从 Unix 纳秒时间戳提取小时 (0-23)
func hourFromTimestamp(ns int64) int {
	return time.Unix(0, ns).Hour()
}

// ensureDayTable 确保按天分表存在并创建索引
func ensureDayTable(db *gorm.DB, tableName string) error {
	if db.Migrator().HasTable(tableName) {
		return nil
	}

	if err := db.Table(tableName).AutoMigrate(&models.EgresslogRecord{}); err != nil {
		return fmt.Errorf("auto migrate table %s: %w", tableName, err)
	}

	indexes := []struct {
		name string
		sql  string
	}{
		{"idx_hour", fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_hour ON %s (hour)", tableName, tableName)},
		{"idx_dst_ip", fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_dst_ip ON %s (dst_ip)", tableName, tableName)},
		{"idx_timestamp", fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_timestamp ON %s (timestamp)", tableName, tableName)},
	}
	for _, idx := range indexes {
		if err := db.Exec(idx.sql).Error; err != nil {
			logger.Warnf("[EgressLog] Failed to create index %s on %s: %v", idx.name, tableName, err)
		}
	}

	logger.Infof("[EgressLog] Created daily table: %s", tableName)
	return nil
}
