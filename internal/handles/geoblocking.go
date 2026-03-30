package handles

import (
	"rho-aias/internal/geoblocking"
	"rho-aias/internal/logger"
	"rho-aias/internal/response"

	"github.com/gin-gonic/gin"
)

// GeoBlockingHandle Geo-Blocking API 处理器
type GeoBlockingHandle struct {
	manager *geoblocking.Manager
}

// NewGeoBlockingHandle 创建新的 Geo-Blocking 处理器
func NewGeoBlockingHandle(manager *geoblocking.Manager) *GeoBlockingHandle {
	return &GeoBlockingHandle{
		manager: manager,
	}
}

// GetStatus 获取 Geo-Blocking 状态
func (h *GeoBlockingHandle) GetStatus(c *gin.Context) {
	status := h.manager.GetStatus()
	response.OK(c, status)
}

// TriggerUpdate 手动触发 GeoIP 更新
func (h *GeoBlockingHandle) TriggerUpdate(c *gin.Context) {
	logger.Info("[API] Geo-Blocking manual update triggered")

	if err := h.manager.TriggerUpdate(); err != nil {
		response.InternalError(c, "Update failed: "+err.Error())
		return
	}

	response.OKMsg(c, "Update triggered successfully")
}

// UpdateConfigRequest 更新配置请求结构
type UpdateConfigRequest struct {
	Mode             string   `json:"mode" binding:"required"` // whitelist 或 blacklist
	AllowedCountries []string `json:"allowed_countries"`        // 允许的国家代码列表
}

// UpdateConfig 更新 Geo-Blocking 配置
func (h *GeoBlockingHandle) UpdateConfig(c *gin.Context) {
	var req UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	// 验证模式
	if req.Mode != "whitelist" && req.Mode != "blacklist" {
		response.BadRequest(c, "Invalid mode, must be 'whitelist' or 'blacklist'")
		return
	}

	if err := h.manager.UpdateConfig(req.Mode, req.AllowedCountries); err != nil {
		response.InternalError(c, "Update config failed: "+err.Error())
		return
	}

	response.OKMsg(c, "Configuration updated successfully")
}
