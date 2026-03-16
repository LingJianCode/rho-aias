package services

import (
	"encoding/json"
	"time"

	"rho-aias/internal/models"

	"gorm.io/gorm"
)

// AuditService 审计日志服务
type AuditService struct {
	db *gorm.DB
}

// NewAuditService 创建审计日志服务
func NewAuditService(db *gorm.DB) *AuditService {
	return &AuditService{db: db}
}

// LogRequest 记录审计日志的请求
type LogRequest struct {
	UserID     uint
	Username   string
	Action     string
	Resource   string
	ResourceID string
	Detail     interface{}
	IP         string
	UserAgent  string
	Status     string
	Error      string
}

// Log 记录审计日志
func (s *AuditService) Log(req LogRequest) error {
	// 序列化详情
	var detailStr string
	if req.Detail != nil {
		detailBytes, err := json.Marshal(req.Detail)
		if err != nil {
			detailStr = "{}"
		} else {
			detailStr = string(detailBytes)
		}
	}

	log := &models.AuditLog{
		UserID:     req.UserID,
		Username:   req.Username,
		Action:     req.Action,
		Resource:   req.Resource,
		ResourceID: req.ResourceID,
		Detail:     detailStr,
		IP:         req.IP,
		UserAgent:  req.UserAgent,
		Status:     req.Status,
		Error:      req.Error,
		CreatedAt:  time.Now(),
	}

	// 默认状态为成功
	if log.Status == "" {
		log.Status = "success"
	}

	return s.db.Create(log).Error
}

// ListLogsRequest 列出日志的请求参数
type ListLogsRequest struct {
	Page      int    `form:"page"`
	PageSize  int    `form:"page_size"`
	UserID    uint   `form:"user_id"`
	Action    string `form:"action"`
	Resource  string `form:"resource"`
	StartTime string `form:"start_time"`
	EndTime   string `form:"end_time"`
	Status    string `form:"status"`
}

// ListLogsResponse 列出日志的响应
type ListLogsResponse struct {
	Total int64             `json:"total"`
	Logs  []models.AuditLog `json:"logs"`
}

// ListLogs 列出审计日志
func (s *AuditService) ListLogs(req ListLogsRequest) (*ListLogsResponse, error) {
	// 设置默认值
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}
	if req.PageSize > 100 {
		req.PageSize = 100
	}

	query := s.db.Model(&models.AuditLog{})

	// 构建查询条件
	if req.UserID > 0 {
		query = query.Where("user_id = ?", req.UserID)
	}
	if req.Action != "" {
		query = query.Where("action = ?", req.Action)
	}
	if req.Resource != "" {
		query = query.Where("resource = ?", req.Resource)
	}
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}
	if req.StartTime != "" {
		query = query.Where("created_at >= ?", req.StartTime)
	}
	if req.EndTime != "" {
		query = query.Where("created_at <= ?", req.EndTime)
	}

	// 统计总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	// 分页查询
	var logs []models.AuditLog
	offset := (req.Page - 1) * req.PageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(req.PageSize).Find(&logs).Error; err != nil {
		return nil, err
	}

	return &ListLogsResponse{
		Total: total,
		Logs:  logs,
	}, nil
}

// GetLogByID 根据 ID 获取审计日志
func (s *AuditService) GetLogByID(id uint) (*models.AuditLog, error) {
	var log models.AuditLog
	if err := s.db.First(&log, id).Error; err != nil {
		return nil, err
	}
	return &log, nil
}

// CleanOldLogs 清理旧日志（保留最近N天）
func (s *AuditService) CleanOldLogs(retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	return s.db.Where("created_at < ?", cutoff).Delete(&models.AuditLog{}).Error
}
