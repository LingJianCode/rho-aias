package services

import (
	"fmt"
	"time"

	"rho-aias/internal/logger"
	"rho-aias/internal/models"

	"gorm.io/gorm"
)

// chinaLocation 中国时区 (UTC+8)
var chinaLocation *time.Location

func init() {
	var err error
	chinaLocation, err = time.LoadLocation("Asia/Shanghai")
	if err != nil {
		// 如果加载失败，使用固定偏移量 UTC+8
		logger.Warnf("Failed to load timezone Asia/Shanghai, using FixedZone CST+0800: %v", err)
		chinaLocation = time.FixedZone("CST", 8*60*60)
	}
}

// parseLocalTime 解析本地时间字符串 (假设为中国时区 UTC+8)
// 支持格式:
//   - "2006-01-02 15:04:05" (推荐，前端 el-date-picker 使用)
//   - time.RFC3339: "2006-01-02T15:04:05Z07:00" (向后兼容)
func parseLocalTime(timeStr string) (time.Time, error) {
	// 1. 先尝试 "2006-01-02 15:04:05" 格式 (中国时区)
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", timeStr, chinaLocation); err == nil {
		return t, nil
	}

	// 2. 尝试 RFC3339 格式 (向后兼容)
	if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("无法解析时间格式: %s (支持格式: 2006-01-02 15:04:05 或 RFC3339)", timeStr)
}

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
	IP        string `form:"ip"`         // 按封禁 IP 过滤
	Source    string `form:"source"`     // 按来源过滤: waf, rate_limit, anomaly, manual, failguard
	Status    string `form:"status"`     // 按状态过滤: active, expired, manual_unblock
	StartTime string `form:"start_time"` // 开始时间 (格式: "2006-01-02 15:04:05" 中国时区，或 RFC3339)
	EndTime   string `form:"end_time"`   // 结束时间 (格式: "2006-01-02 15:04:05" 中国时区，或 RFC3339)
	Limit     int    `form:"limit"`      // 限制返回条数
	Offset    int    `form:"offset"`     // 偏移量（分页）
	OrderBy   string `form:"order_by"`   // 排序字段: created_at, ip, source (默认 created_at)
	Order     string `form:"order"`      // 排序方向: asc, desc (默认 desc)
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
	// 时间范围过滤 (支持 "2006-01-02 15:04:05" 中国时区格式)
	if filter.StartTime != "" {
		if t, err := parseLocalTime(filter.StartTime); err == nil {
			query = query.Where("created_at >= ?", t)
		}
	}
	if filter.EndTime != "" {
		if t, err := parseLocalTime(filter.EndTime); err == nil {
			query = query.Where("created_at <= ?", t)
		}
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
	if err := s.db.Model(&models.BanRecord{}).Count(&stats.Total).Error; err != nil {
		return nil, fmt.Errorf("failed to count total ban records: %w", err)
	}

	// 按来源统计
	var bySource []struct {
		Source string
		Count  int64
	}
	if err := s.db.Model(&models.BanRecord{}).Select("source, count(*) as count").Group("source").Find(&bySource).Error; err != nil {
		return nil, fmt.Errorf("failed to count ban records by source: %w", err)
	}
	for _, item := range bySource {
		stats.BySource[item.Source] = item.Count
	}

	// 按状态统计
	var byStatus []struct {
		Status string
		Count  int64
	}
	if err := s.db.Model(&models.BanRecord{}).Select("status, count(*) as count").Group("status").Find(&byStatus).Error; err != nil {
		return nil, fmt.Errorf("failed to count ban records by status: %w", err)
	}
	for _, item := range byStatus {
		stats.ByStatus[item.Status] = item.Count
	}
	stats.Active = stats.ByStatus["active"]

	// Top 封禁 IP
	var topIPs []TopIPStat
	if err := s.db.Model(&models.BanRecord{}).Select("ip, count(*) as count").
		Group("ip").Order("count DESC").Limit(10).
		Find(&topIPs).Error; err != nil {
		return nil, fmt.Errorf("failed to get top banned IPs: %w", err)
	}
	stats.TopIPs = topIPs

	return stats, nil
}

// UpsertActiveBan 插入或忽略：如果同一 IP+来源已存在 active 记录则跳过
func (s *BanRecordService) UpsertActiveBan(ip, source, reason string, duration int) error {
	var count int64
	s.db.Model(&models.BanRecord{}).
		Where("ip = ? AND source = ? AND status = ?", ip, source, models.BanStatusActive).
		Count(&count)
	if count > 0 {
		return nil
	}

	now := time.Now()
	return s.db.Create(&models.BanRecord{
		IP:        ip,
		Source:    source,
		Reason:    reason,
		Duration:  duration,
		Status:    models.BanStatusActive,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(duration) * time.Second),
	}).Error
}

// GetRecordByID 根据 ID 获取封禁记录
func (s *BanRecordService) GetRecordByID(id uint) (*models.BanRecord, error) {
	var record models.BanRecord
	err := s.db.First(&record, id).Error
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// UpdateStatusByID 根据 ID 更新封禁状态
func (s *BanRecordService) UpdateStatusByID(id uint, status string) error {
	now := time.Now()
	updates := map[string]interface{}{
		"status": status,
	}
	// 如果是解封状态，记录解封时间
	if status == models.BanStatusManualUnblock || status == models.BanStatusAutoUnblock {
		updates["unblocked_at"] = &now
	}
	return s.db.Model(&models.BanRecord{}).Where("id = ?", id).Updates(updates).Error
}

// MarkAllActiveAsAutoUnblock 将所有 active 状态的记录标记为 auto_unblock
// 用于系统启动时，因为 eBPF map 状态丢失
func (s *BanRecordService) MarkAllActiveAsAutoUnblock() (int64, error) {
	now := time.Now()
	result := s.db.Model(&models.BanRecord{}).
		Where("status = ?", models.BanStatusActive).
		Updates(map[string]interface{}{
			"status":       models.BanStatusAutoUnblock,
			"unblocked_at": &now,
		})
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}


