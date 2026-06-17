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
		logger.Errorf("GeoBlocking TriggerUpdate failed: %v", err)
		response.InternalError(c, "internal server error")
		return
	}

	response.OKMsg(c, "Update triggered successfully")
}
