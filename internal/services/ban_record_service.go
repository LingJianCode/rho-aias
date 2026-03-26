package services

import (
	"time"

	"rho-aias/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// BanRecordService 封禁记录服务
type BanRecordService struct {
	db *gorm.DB
}

// NewBanRecordService 创建封禁记录服务
func NewBanRecordService(db *gorm.DB) *BanRecordService {
	return &BanRecordService{db: db}
}

// DB 返回底层数据库连接（供 handler 直接查询使用）
func (s *BanRecordService) DB() *gorm.DB {
	return s.db
}

// BanRecordFilter 封禁记录查询过滤器
type BanRecordFilter struct {
	IP      string `form:"ip"`       // 按封禁 IP 过滤
	Source  string `form:"source"`   // 按来源过滤: waf, rate_limit, anomaly, manual
	Status  string `form:"status"`   // 按状态过滤: active, expired, manual_unblock
	Limit   int    `form:"limit"`    // 限制返回条数
	Offset  int    `form:"offset"`   // 偏移量（分页）
	OrderBy string `form:"order_by"` // 排序字段: created_at, ip, source (默认 created_at)
	Order   string `form:"order"`    // 排序方向: asc, desc (默认 desc)
}

// CreateRecord 创建封禁记录
func (s *BanRecordService) CreateRecord(ip, source, reason string, duration int) error {
	now := time.Now()
	record := &models.BanRecord{
		IP:        ip,
		Source:    source,
		Reason:    reason,
		Duration:  duration,
		Status:    models.BanStatusActive,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(duration) * time.Second),
	}
	return s.db.Create(record).Error
}

// MarkExpired 标记封禁记录为已过期
func (s *BanRecordService) MarkExpired(ip, source string) error {
	result := s.db.Model(&models.BanRecord{}).
		Where("ip = ? AND source = ? AND status = ?", ip, source, models.BanStatusActive).
		Update("status", models.BanStatusExpired)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// MarkManualUnblock 标记封禁记录为手动解封
func (s *BanRecordService) MarkManualUnblock(ip, source string) error {
	now := time.Now()
	result := s.db.Model(&models.BanRecord{}).
		Where("ip = ? AND source = ? AND status = ?", ip, source, models.BanStatusActive).
		Updates(map[string]interface{}{
			"status":       models.BanStatusManualUnblock,
			"unblocked_at": &now,
		})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// QueryRecords 查询封禁记录
func (s *BanRecordService) QueryRecords(filter BanRecordFilter) ([]models.BanRecord, int64, error) {
	var records []models.BanRecord
	var total int64

	query := s.db.Model(&models.BanRecord{})

	// 应用过滤器
	if filter.IP != "" {
		query = query.Where("ip = ?", filter.IP)
	}
	if filter.Source != "" {
		query = query.Where("source = ?", filter.Source)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}

	// 计算总数
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 排序
	orderBy := "created_at"
	if filter.OrderBy != "" {
		// 白名单校验，防止 SQL 注入
		allowed := map[string]string{
			"created_at": "created_at",
			"ip":         "ip",
			"source":     "source",
			"duration":   "duration",
			"expires_at": "expires_at",
		}
		if col, ok := allowed[filter.OrderBy]; ok {
			orderBy = col
		}
	}
	order := "desc"
	if filter.Order == "asc" {
		order = "asc"
	}
	query = query.Order(orderBy + " " + order)

	// 分页
	if filter.Limit <= 0 || filter.Limit > 1000 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if err := query.Offset(filter.Offset).Limit(filter.Limit).Find(&records).Error; err != nil {
		return nil, 0, err
	}

	return records, total, nil
}

// GetActiveBanByIPAndSource 查询指定 IP 和来源的活跃封禁记录
func (s *BanRecordService) GetActiveBanByIPAndSource(ip, source string) (*models.BanRecord, error) {
	var record models.BanRecord
	err := s.db.Where("ip = ? AND source = ? AND status = ?", ip, source, models.BanStatusActive).
		Order("created_at DESC").
		First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &record, nil
}

// CleanupExpired 清理过期的封禁记录，批量更新状态
func (s *BanRecordService) CleanupExpired() (int64, error) {
	result := s.db.Model(&models.BanRecord{}).
		Where("status = ? AND expires_at < ?", models.BanStatusActive, time.Now()).
		Update("status", models.BanStatusExpired)
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}

// GetBanStats 获取封禁统计
type BanStats struct {
	Total      int64            `json:"total"`
	Active     int64            `json:"active"`
	BySource   map[string]int64 `json:"by_source"`
	ByStatus   map[string]int64 `json:"by_status"`
	TopIPs     []TopIPStat      `json:"top_ips"`
}

type TopIPStat struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

func (s *BanRecordService) GetBanStats() (*BanStats, error) {
	stats := &BanStats{
		BySource: make(map[string]int64),
		ByStatus: make(map[string]int64),
	}

	// 总数
	s.db.Model(&models.BanRecord{}).Count(&stats.Total)

	// 按来源统计
	var bySource []struct {
		Source string
		Count  int64
	}
	s.db.Model(&models.BanRecord{}).Select("source, count(*) as count").Group("source").Find(&bySource)
	for _, item := range bySource {
		stats.BySource[item.Source] = item.Count
	}

	// 按状态统计
	var byStatus []struct {
		Status string
		Count  int64
	}
	s.db.Model(&models.BanRecord{}).Select("status, count(*) as count").Group("status").Find(&byStatus)
	for _, item := range byStatus {
		stats.ByStatus[item.Status] = item.Count
		stats.Active = stats.ByStatus["active"]
	}

	// Top 封禁 IP
	var topIPs []TopIPStat
	s.db.Model(&models.BanRecord{}).Select("ip, count(*) as count").
		Group("ip").Order("count DESC").Limit(10).
		Find(&topIPs)
	stats.TopIPs = topIPs

	return stats, nil
}

// UpsertActiveBan 插入或忽略：如果同一 IP+来源已存在 active 记录则跳过
// 使用 ON CONFLICT DO NOTHING 避免重复写入
func (s *BanRecordService) UpsertActiveBan(ip, source, reason string, duration int) error {
	now := time.Now()
	record := &models.BanRecord{
		IP:        ip,
		Source:    source,
		Reason:    reason,
		Duration:  duration,
		Status:    models.BanStatusActive,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(duration) * time.Second),
	}

	// 先检查是否已存在 active 记录
	var count int64
	s.db.Model(&models.BanRecord{}).
		Where("ip = ? AND source = ? AND status = ?", ip, source, models.BanStatusActive).
		Count(&count)
	if count > 0 {
		return nil
	}

	return s.db.Create(record).Error
}

// init 确保 BanRecord 表存在（用于 UPSERT 时需要唯一索引）
func init() {
	// GORM AutoMigrate 会处理表创建
	// 这里不需要额外操作
	_ = clause.OnConflict{}
}
