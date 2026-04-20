// Package blocklog 阻断日志模块
package blocklog

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
	BufferSize    int           // 异步写入缓冲区大小
	FlushInterval time.Duration // 刷盘间隔
}

// AsyncWriter 异步日志写入器（写入 SQLite 按天分表）
type AsyncWriter struct {
	config     Config
	db         *gorm.DB
	statsStore *StatsStore // 用于定时清理
	recordCh   chan BlockRecord
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
		recordCh: make(chan BlockRecord, config.BufferSize),
		stopCh:   make(chan struct{}),
		flushCh:  make(chan chan struct{}, 1),
	}

	// 初始化 Cron 定时任务
	aw.cron = cron.New(cron.WithSeconds())

	// 添加定时刷新任务
	flushExpr := "@every " + config.FlushInterval.String()
	if _, err := aw.cron.AddFunc(flushExpr, func() {
		aw.Flush()
	}); err != nil {
		return nil, fmt.Errorf("failed to add flush cron job: %w", err)
	}

	// 整点轮转回调（每小时第 3 分钟执行，聚合上一小时数据，避免整点临界时刻缓冲区未落盘）
	if onRotate != nil {
		if _, err := aw.cron.AddFunc("0 3 * * * *", func() {
			lastHour := time.Now().Add(-1 * time.Hour)
			onRotate(lastHour)
		}); err != nil {
			return nil, fmt.Errorf("failed to add rotate cron job: %w", err)
		}
	}

	// 每天凌晨 3:00 清理过期数据（按天分表 + 小时统计表）
	if aw.statsStore != nil {
		if _, err := aw.cron.AddFunc("0 0 3 * * *", func() {
			if err := aw.statsStore.CleanupOldDayTables(defaultRetentionDays); err != nil {
				logger.Warnf("[BlockLog] Daily cleanup of old tables failed: %v", err)
			}
			if err := aw.statsStore.CleanupOldHourlyData(defaultRetentionDays); err != nil {
				logger.Warnf("[BlockLog] Daily cleanup of old hourly stats failed: %v", err)
			}
		}); err != nil {
			return nil, fmt.Errorf("failed to add cleanup cron job: %w", err)
		}
	}

	// 启动定时任务
	aw.cron.Start()

	// 启动后台写入协程
	aw.wg.Add(1)
	go aw.run()

	return aw, nil
}

// Write 异步写入一条记录
func (aw *AsyncWriter) Write(record BlockRecord) error {
	aw.stopMu.RLock()
	stopped := aw.stopped
	aw.stopMu.RUnlock()

	if stopped {
		return nil
	}

	// 非阻塞写入，如果通道满了就丢弃
	select {
	case aw.recordCh <- record:
	default:
		logger.Warnf("[BlockLog] Channel full (size=%d), dropping record: srcIP=%s, matchType=%s, timestamp=%d",
			cap(aw.recordCh), record.SrcIP, record.MatchType, record.Timestamp)
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

	// 停止 Cron 定时任务
	if aw.cron != nil {
		aw.cron.Stop()
	}

	// 发送停止信号
	close(aw.stopCh)

	// 等待写入协程结束
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
		// 已有一个 flush 请求在处理
	}
	return nil
}

// run 后台写入协程
func (aw *AsyncWriter) run() {
	defer aw.wg.Done()

	var pendingRecords []BlockRecord

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
func (aw *AsyncWriter) writeBatch(records []BlockRecord) {
	if aw.db == nil || len(records) == 0 {
		return
	}

	// 按天分组
	groups := make(map[string][]BlockRecord)
	for _, r := range records {
		dayKey := dayKeyFromTimestamp(r.Timestamp)
		groups[dayKey] = append(groups[dayKey], r)
	}

	for dayKey, recs := range groups {
		tableName := "blocklog_" + dayKey

		// 确保表存在
		if err := ensureDayTable(aw.db, tableName); err != nil {
			logger.Errorf("[BlockLog] Failed to ensure table %s: %v", tableName, err)
			continue
		}

		// 批量 INSERT（单事务）
		err := aw.db.Transaction(func(tx *gorm.DB) error {
			for _, r := range recs {
				row := models.BlocklogRecord{
					Hour:        hourFromTimestamp(r.Timestamp),
					Timestamp:   r.Timestamp,
					SrcIP:       r.SrcIP,
					DstIP:       r.DstIP,
					DstPort:     r.DstPort,
					MatchType:   r.MatchType,
					RuleSource:  r.RuleSource,
					CountryCode: r.CountryCode,
					PacketSize:  r.PacketSize,
				}
				if err := tx.Table(tableName).Create(&row).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			logger.Errorf("[BlockLog] Batch insert to %s failed (%d records): %v", tableName, len(recs), err)
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
	// 检查表是否已存在
	if db.Migrator().HasTable(tableName) {
		return nil
	}

	// 创建表
	if err := db.Table(tableName).AutoMigrate(&models.BlocklogRecord{}); err != nil {
		return fmt.Errorf("auto migrate table %s: %w", tableName, err)
	}

	// 创建额外索引（GORM AutoMigrate 仅创建 tag 中声明的索引，这里补充复合索引用于查询优化）
	indexes := []struct {
		name string
		sql  string
	}{
		{"idx_hour", fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_hour ON %s (hour)", tableName, tableName)},
		{"idx_src_ip", fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_src_ip ON %s (src_ip)", tableName, tableName)},
		{"idx_match_type", fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_match_type ON %s (match_type)", tableName, tableName)},
		{"idx_rule_source", fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_rule_source ON %s (rule_source)", tableName, tableName)},
		{"idx_timestamp", fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_timestamp ON %s (timestamp)", tableName, tableName)},
	}
	for _, idx := range indexes {
		if err := db.Exec(idx.sql).Error; err != nil {
			logger.Warnf("[BlockLog] Failed to create index %s on %s: %v", idx.name, tableName, err)
		}
	}

	logger.Infof("[BlockLog] Created daily table: %s", tableName)
	return nil
}
