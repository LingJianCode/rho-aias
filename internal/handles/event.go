package handles

import (
	"log"
	"net/http"
	"rho-aias/internal/ebpfs"

	"github.com/gin-gonic/gin"
)

// EventHandle 事件上报配置 API 处理器
type EventHandle struct {
	xdp *ebpfs.Xdp
}

// NewEventHandle 创建新的事件配置处理器
func NewEventHandle(xdp *ebpfs.Xdp) *EventHandle {
	return &EventHandle{
		xdp: xdp,
	}
}

// EventConfigRequest 事件配置请求结构
type EventConfigRequest struct {
	Enabled    *bool  `json:"enabled"`     // 是否启用事件上报
	SampleRate *uint32 `json:"sample_rate"` // 采样率
}

// EventStatusResponse 事件状态响应结构
type EventStatusResponse struct {
	Enabled    bool   `json:"enabled"`     // 是否启用
	SampleRate uint32 `json:"sample_rate"` // 采样率
}

// SetEventConfig 设置事件上报配置
// POST /api/xdp/events/config
func (h *EventHandle) SetEventConfig(c *gin.Context) {
	var req EventConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误: " + err.Error(),
		})
		return
	}

	// 获取当前配置
	currentConfig, _ := h.xdp.GetEventConfig()

	// 更新配置（只更新请求中提供的字段）
	enabled := currentConfig.Enabled == 1
	sampleRate := currentConfig.SampleRate

	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.SampleRate != nil {
		sampleRate = *req.SampleRate
		// 确保采样率至少为 1
		if sampleRate == 0 {
			sampleRate = 1
		}
	}

	// 设置新配置
	if err := h.xdp.SetEventConfig(enabled, sampleRate); err != nil {
		log.Printf("[Event] Failed to set event config: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "设置配置失败: " + err.Error(),
		})
		return
	}

	log.Printf("[Event] Event config updated: enabled=%v, sample_rate=%d", enabled, sampleRate)

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "ok",
		"data": EventStatusResponse{
			Enabled:    enabled,
			SampleRate: sampleRate,
		},
	})
}

// GetEventStatus 获取事件上报状态
// GET /api/xdp/events/status
func (h *EventHandle) GetEventStatus(c *gin.Context) {
	config, err := h.xdp.GetEventConfig()
	if err != nil {
		// 如果查询失败，返回默认配置（关闭状态）
		config = ebpfs.DefaultEventConfig()
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "ok",
		"data": EventStatusResponse{
			Enabled:    config.Enabled == 1,
			SampleRate: config.SampleRate,
		},
	})
}
