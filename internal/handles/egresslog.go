package handles

import (
	"strconv"
	"time"

	"rho-aias/internal/egresslog"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/response"

	"github.com/gin-gonic/gin"
)

// EgressLogHandle Egress 丢包日志 API 处理器
type EgressLogHandle struct {
	egressLog *egresslog.Manager
	tcEgress  *ebpfs.TcEgress
}

// NewEgressLogHandle 创建新的 Egress 丢包日志处理器
func NewEgressLogHandle(egressLog *egresslog.Manager, tcEgress *ebpfs.TcEgress) *EgressLogHandle {
	return &EgressLogHandle{
		egressLog: egressLog,
		tcEgress:  tcEgress,
	}
}

// GetRecords 获取丢包记录
// GET /api/egresslog/records?date=2026-04-17&start_hour=0&end_hour=23&page=1&page_size=20&dst_ip=
func (h *EgressLogHandle) GetRecords(c *gin.Context) {
	var filter egresslog.RecordFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		response.BadRequest(c, "Invalid query parameters: "+err.Error())
		return
	}

	if filter.Date == "" {
		filter.Date = time.Now().Format("2006-01-02")
	}

	if filter.StartHour == nil {
		defaultStart := 0
		filter.StartHour = &defaultStart
	} else if *filter.StartHour < 0 || *filter.StartHour > 23 {
		defaultStart := 0
		filter.StartHour = &defaultStart
	}
	if filter.EndHour == nil {
		defaultEnd := 23
		filter.EndHour = &defaultEnd
	} else if *filter.EndHour < 0 || *filter.EndHour > 23 {
		defaultEnd := 23
		filter.EndHour = &defaultEnd
	}
	if *filter.StartHour > *filter.EndHour {
		response.BadRequest(c, "start_hour must be <= end_hour")
		return
	}

	result, err := h.egressLog.QueryRecords(filter)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.OK(c, result)
}

// GetStats 获取丢包统计
// GET /api/egresslog/stats
func (h *EgressLogHandle) GetStats(c *gin.Context) {
	stats := h.egressLog.GetStats()
	response.OK(c, stats)
}

// GetTopDroppedIPs 获取丢包 Top IP 列表
// GET /api/egresslog/top-ips?limit=20
func (h *EgressLogHandle) GetTopDroppedIPs(c *gin.Context) {
	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	topIPs := h.egressLog.GetTopIPs(limit)

	response.OK(c, gin.H{
		"top_dropped_ips": topIPs,
	})
}

// GetHourlyTrend 获取丢包计数小时趋势
// GET /api/egresslog/hourly-trend?hours=24
func (h *EgressLogHandle) GetHourlyTrend(c *gin.Context) {
	hours := 24
	if h := c.Query("hours"); h != "" {
		if parsed, err := strconv.Atoi(h); err == nil && parsed > 0 && parsed <= 720 {
			hours = parsed
		}
	}

	trend := h.egressLog.GetHourlyTrend(hours)

	response.OK(c, gin.H{
		"hours":       hours,
		"hourly_data": trend,
	})
}

// DropLogStatusResponse 丢包日志状态响应结构
type DropLogStatusResponse struct {
	Enabled    bool   `json:"enabled"`     // 是否启用
	SampleRate uint32 `json:"sample_rate"` // 采样率
}

// GetDropLogStatus 获取丢包日志上报状态
// GET /api/egresslog/drop-log-status
func (h *EgressLogHandle) GetDropLogStatus(c *gin.Context) {
	if h.tcEgress == nil {
		response.OK(c, DropLogStatusResponse{Enabled: false, SampleRate: 0})
		return
	}
	config, err := h.tcEgress.GetDropLogConfig()
	if err != nil {
		config = ebpfs.DefaultEgressDropEventConfig()
	}

	response.OK(c, DropLogStatusResponse{
		Enabled:    config.Enabled == 1,
		SampleRate: config.SampleRate,
	})
}
