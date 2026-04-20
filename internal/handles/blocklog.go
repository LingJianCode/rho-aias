package handles

import (
	"strconv"
	"time"

	"rho-aias/internal/blocklog"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/response"

	"github.com/gin-gonic/gin"
)

// BlockLogHandle 阻断日志 API 处理器
type BlockLogHandle struct {
	blockLog *blocklog.Manager
	xdp      *ebpfs.Xdp
}

// NewBlockLogHandle 创建新的阻断日志处理器
func NewBlockLogHandle(blockLog *blocklog.Manager, xdp *ebpfs.Xdp) *BlockLogHandle {
	return &BlockLogHandle{
		blockLog: blockLog,
		xdp:      xdp,
	}
}

// GetRecords 获取阻断记录
// GET /api/blocklog/records?date=2026-04-17&start_hour=0&end_hour=23&page=1&page_size=20&match_type=&rule_source=&src_ip=&country_code=
// 必须指定 date 参数；start_hour/end_hour 默认为 0/23（当天全部）；不支持跨天查询
func (h *BlockLogHandle) GetRecords(c *gin.Context) {
	var filter blocklog.RecordFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		response.BadRequest(c, "Invalid query parameters: "+err.Error())
		return
	}

	if filter.Date == "" {
		filter.Date = time.Now().Format("2006-01-02")
	}

	// 设置默认小时范围
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

	result, err := h.blockLog.QueryRecords(filter)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.OK(c, result)
}

// GetStats 获取阻断统计
// GET /api/blocklog/stats
func (h *BlockLogHandle) GetStats(c *gin.Context) {
	stats := h.blockLog.GetStats()

	response.OK(c, stats)
}

// GetBlockedTopIPs 获取被阻断的 IP 列表（直接从 DB 查询）
// GET /api/blocklog/blocked-top-ips?limit=20
func (h *BlockLogHandle) GetBlockedTopIPs(c *gin.Context) {
	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := parseInt(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	topIPs := h.blockLog.GetTopIPs(limit)

	response.OK(c, gin.H{
		"top_blocked_ips": topIPs,
	})
}

// GetHourlyTrend 获取丢弃计数小时趋势
// GET /api/blocklog/hourly-trend?hours=24&by=source
func (h *BlockLogHandle) GetHourlyTrend(c *gin.Context) {
	hours := 24 // 默认查询最近 24 小时
	if h := c.Query("hours"); h != "" {
		if parsed, err := parseInt(h); err == nil && parsed > 0 && parsed <= 720 {
			hours = parsed
		}
	}

	trend := h.blockLog.GetHourlyTrend(hours)

	response.OK(c, gin.H{
		"hours":       hours,
		"hourly_data": trend,
	})
}

func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

// EventStatusResponse 事件状态响应结构
type EventStatusResponse struct {
	Enabled    bool   `json:"enabled"`     // 是否启用
	SampleRate uint32 `json:"sample_rate"` // 采样率
}

// EnrichCountryCode 手动触发 IP 归属地补全（异步）
// POST /api/blocklog/enrich-country
// Body: {"date": "2026-04-20"}
func (h *BlockLogHandle) EnrichCountryCode(c *gin.Context) {
	var req struct {
		Date string `json:"date" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "date is required (format: 2026-04-20)")
		return
	}

	// 验证日期格式
	if _, err := time.Parse("2006-01-02", req.Date); err != nil {
		response.BadRequest(c, "invalid date format, expected YYYY-MM-DD")
		return
	}

	if err := h.blockLog.EnrichCountryCode(req.Date); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	response.OK(c, gin.H{
		"message": "enrichment started",
		"date":    req.Date,
	})
}

// GetEventStatus 获取阻断事件上报状态
// GET /api/blocklog/event-status
func (h *BlockLogHandle) GetEventStatus(c *gin.Context) {
	if h.xdp == nil {
		response.OK(c, EventStatusResponse{Enabled: false, SampleRate: 0})
		return
	}
	config, err := h.xdp.GetBlocklogEventConfig()
	if err != nil {
		config = ebpfs.DefaultBlocklogEventConfig()
	}

	response.OK(c, EventStatusResponse{
		Enabled:    config.Enabled == 1,
		SampleRate: config.SampleRate,
	})
}
