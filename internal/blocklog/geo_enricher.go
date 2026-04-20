package blocklog

import (
	"fmt"
	"sync"
	"time"

	"rho-aias/internal/logger"

	"github.com/robfig/cron/v3"
)

// GeoLookup IP 归属地查询接口（由 geoblocking 模块实现注入）
type GeoLookup interface {
	LookupCountry(ip string) (string, error)
}

// GeoEnricher IP 归属地补全器
type GeoEnricher struct {
	db        *StatsStore
	geoLookup GeoLookup
	cron      *cron.Cron
	batchSize int
	enabled   bool

	// 异步任务状态追踪
	mu          sync.Mutex      // 保护 runningJobs
	runningJobs map[string]bool // date -> 是否正在执行
}

// NewGeoEnricher 创建 IP 归属地补全器
func NewGeoEnricher(db *StatsStore, geoLookup GeoLookup, enabled bool, batchSize int) *GeoEnricher {
	if batchSize <= 0 {
		batchSize = 500
	}
	return &GeoEnricher{
		db:          db,
		geoLookup:   geoLookup,
		batchSize:   batchSize,
		enabled:     enabled,
		runningJobs: make(map[string]bool),
	}
}

// Start 启动定时任务（每小时第 5 分钟，只处理当天）
func (e *GeoEnricher) Start() error {
	if !e.enabled || e.geoLookup == nil {
		logger.Info("[GeoEnricher] Disabled or GeoLookup not available, skipping start")
		return nil
	}

	e.cron = cron.New(cron.WithSeconds())

	// 每小时第 5 分钟执行当天分表的补全
	if _, err := e.cron.AddFunc("0 5 * * * *", func() {
		today := time.Now().Format("2006-01-02")
		if err := e.enrichDay(today); err != nil {
			logger.Errorf("[GeoEnricher] Scheduled enrichment for %s failed: %v", today, err)
		}
	}); err != nil {
		return fmt.Errorf("failed to add geo enrich cron job: %w", err)
	}

	e.cron.Start()
	logger.Info("[GeoEnricher] Started with schedule: 0 5 * * * *")
	return nil
}

// Stop 停止补全器
func (e *GeoEnricher) Stop() {
	if e.cron != nil {
		e.cron.Stop()
		logger.Info("[GeoEnricher] Stopped")
	}
}

// EnrichDay 异步按天补全（供手动 API 调用）
func (e *GeoEnricher) EnrichDay(date string) error {
	if e.geoLookup == nil {
		return fmt.Errorf("geo lookup not available")
	}

	// 验证日期格式
	if _, err := time.Parse("2006-01-02", date); err != nil {
		return fmt.Errorf("invalid date format, expected YYYY-MM-DD")
	}

	e.mu.Lock()
	if e.runningJobs[date] {
		e.mu.Unlock()
		return fmt.Errorf("enrichment for %s is already running", date)
	}
	e.runningJobs[date] = true
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			delete(e.runningJobs, date)
			e.mu.Unlock()
		}()

		if err := e.enrichDay(date); err != nil {
			logger.Errorf("[GeoEnricher] Enrichment for %s failed: %v", date, err)
		}
	}()

	return nil
}

// enrichDay 同步执行按天补全逻辑
func (e *GeoEnricher) enrichDay(date string) error {
	parsedDate, err := time.Parse("2006-01-02", date)
	if err != nil {
		return fmt.Errorf("invalid date: %w", err)
	}

	tableName := "blocklog_" + parsedDate.Format("20060102")

	// 检查表是否存在
	if !e.db.TableExists(tableName) {
		return fmt.Errorf("table %s does not exist", tableName)
	}

	logger.Infof("[GeoEnricher] Starting enrichment for %s (table: %s)", date, tableName)

	// 分批查询并处理
	totalEnriched := 0
	for {
		// 查询 country_code 为空的记录（按 src_ip 去重）
		ipRecords, err := e.db.QueryEmptyCountryRecords(tableName, e.batchSize)
		if err != nil {
			return fmt.Errorf("query empty country records failed: %w", err)
		}

		if len(ipRecords) == 0 {
			break
		}

		// 批量查询 IP 归属地
		updates := make(map[uint]string)
		for ip, recordIDs := range ipRecords {
			countryCode, err := e.geoLookup.LookupCountry(ip)
			if err != nil {
				logger.Debugf("[GeoEnricher] Lookup failed for %s: %v", ip, err)
				continue
			}
			if countryCode == "" {
				continue
			}
			for _, id := range recordIDs {
				updates[id] = countryCode
			}
		}

		// 批量更新
		if len(updates) > 0 {
			if err := e.db.BatchUpdateCountryCode(tableName, updates); err != nil {
				return fmt.Errorf("batch update country code failed: %w", err)
			}
			totalEnriched += len(updates)
		}

		// 如果本批次查到的去重 IP 数少于 batchSize，说明已经处理完
		if len(ipRecords) < e.batchSize {
			break
		}
	}

	logger.Infof("[GeoEnricher] Completed enrichment for %s: %d records updated", date, totalEnriched)
	return nil
}
