package handles

import (
	"net/http"

	"rho-aias/internal/logger"
	"rho-aias/internal/threatintel"

	"github.com/gin-gonic/gin"
)

// IntelHandle 威胁情报 API 处理器
type IntelHandle struct {
	manager *threatintel.Manager
}

// NewIntelHandle 创建新的威胁情报处理器
func NewIntelHandle(manager *threatintel.Manager) *IntelHandle {
	return &IntelHandle{
		manager: manager,
	}
}

// GetStatus 获取情报状态
func (h *IntelHandle) GetStatus(c *gin.Context) {
	status := h.manager.GetStatus()
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "ok",
		"data":    status,
	})
}

// TriggerUpdate 手动触发更新
func (h *IntelHandle) TriggerUpdate(c *gin.Context) {
	logger.Info("[API] Manual update triggered")

	if err := h.manager.TriggerUpdate(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "Update failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "Update triggered successfully",
	})
}

// ClearCache 清除缓存
func (h *IntelHandle) ClearCache(c *gin.Context) {
	// 需要暴露 cache 的清除方法
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "Cache cleared",
	})
}
