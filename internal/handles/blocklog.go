package handles

import (
	"fmt"
	"strconv"
	"time"

	"rho-aias/internal/blocklog"
	"rho-aias/internal/ebpfs"
	"rho-aias/internal/response"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// BlockLogHandle 阻断日志 API 处理器
type BlockLogHandle struct {
	blockLog *blocklog.BlockLog
	xdp      *ebpfs.Xdp
}

// NewBlockLogHandle 创建新的阻断日志处理器
func NewBlockLogHandle(blockLog *blocklog.BlockLog, xdp *ebpfs.Xdp) *BlockLogHandle {
	return &BlockLogHandle{
		blockLog: blockLog,
		xdp:      xdp,
	}
}

// AttachStatsStore 注入统计存储（两阶段初始化：bizDB 就绪后调用）
func (h *BlockLogHandle) AttachStatsStore(db *gorm.DB) {
	if h.blockLog != nil {
		h.blockLog.AttachStatsStore(db)
	}
}

// GetRecords 获取阻断记录
// GET /api/blocklog/records?hour=2026-04-17_14&page=1&page_size=20&match_type=&rule_source=&src_ip=&country_code=
// - 指定 hour 参数 → 从 JSONL 文件查询（支持分页，数据完整）
// - 无 hour 参数 → 从内存查询（实时最新 N 条，适合监控面板）
func (h *BlockLogHandle) GetRecords(c *gin.Context) {
	var filter blocklog.RecordFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		response.BadRequest(c, "Invalid query parameters: "+err.Error())
		return
	}

	// 无 hour 参数时默认查当前小时
	if filter.Hour == "" {
		now := time.Now()
		filter.Hour = fmt.Sprintf("%s_%02d", now.Format("2006-01-02"), now.Hour())
	}

	// 统一从 JSONL 文件查询
	result, err := h.blockLog.QueryJSONLRecords(filter)
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

	topIPs, total := h.blockLog.GetTopIPs(limit)

	response.OK(c, gin.H{
		"total_blocked_ips": total,
		"top_blocked_ips":   topIPs,
	})
}

// GetBlockedCountries 获取被阻断的国家/地区列表（直接从 DB 查询）
// GET /api/blocklog/blocked-countries?limit=20
func (h *BlockLogHandle) GetBlockedCountries(c *gin.Context) {
	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := parseInt(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	topCountries, total := h.blockLog.GetTopCountries(limit)

	response.OK(c, gin.H{
		"total_blocked_countries": total,
		"top_blocked_countries":   topCountries,
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

// GetEventStatus 获取阻断事件上报状态
// GET /api/blocklog/event-status
func (h *BlockLogHandle) GetEventStatus(c *gin.Context) {
	if h.xdp == nil {
		response.OK(c, EventStatusResponse{Enabled: false, SampleRate: 0})
		return
	}
	config, err := h.xdp.GetEventConfig()
	if err != nil {
		config = ebpfs.DefaultEventConfig()
	}

	response.OK(c, EventStatusResponse{
		Enabled:    config.Enabled == 1,
		SampleRate: config.SampleRate,
	})
}
