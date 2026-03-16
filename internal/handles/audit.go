package handles

import (
	"net/http"
	"strconv"

	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// AuditHandle 审计日志处理器
type AuditHandle struct {
	auditService *services.AuditService
}

// NewAuditHandle 创建审计日志处理器
func NewAuditHandle(auditService *services.AuditService) *AuditHandle {
	return &AuditHandle{
		auditService: auditService,
	}
}

// ListAuditLogs 列出审计日志
// @Summary 列出审计日志
// @Description 分页查询审计日志
// @Tags 审计日志
// @Produce json
// @Security BearerAuth
// @Param page query int false "页码"
// @Param page_size query int false "每页数量"
// @Param user_id query int false "用户ID"
// @Param action query string false "操作类型"
// @Param resource query string false "资源类型"
// @Param status query string false "状态"
// @Param start_time query string false "开始时间"
// @Param end_time query string false "结束时间"
// @Success 200 {object} services.ListLogsResponse
// @Failure 401 {object} map[string]string
// @Router /api/audit/logs [get]
func (h *AuditHandle) ListAuditLogs(c *gin.Context) {
	var req services.ListLogsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.auditService.ListLogs(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GetAuditLog 获取单条审计日志
// @Summary 获取审计日志
// @Description 根据ID获取审计日志详情
// @Tags 审计日志
// @Produce json
// @Security BearerAuth
// @Param id path int true "日志ID"
// @Success 200 {object} models.AuditLog
// @Failure 401 {object} map[string]string
// @Router /api/audit/logs/{id} [get]
func (h *AuditHandle) GetAuditLog(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid log id"})
		return
	}

	log, err := h.auditService.GetLogByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "log not found"})
		return
	}

	c.JSON(http.StatusOK, log)
}

// CleanAuditLogs 清理旧日志
// @Summary 清理旧日志
// @Description 清理指定天数之前的日志
// @Tags 审计日志
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body map[string]int true "清理请求"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/audit/clean [post]
func (h *AuditHandle) CleanAuditLogs(c *gin.Context) {
	var req struct {
		RetentionDays int `json:"retention_days" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.auditService.CleanOldLogs(req.RetentionDays); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "old logs cleaned successfully"})
}
