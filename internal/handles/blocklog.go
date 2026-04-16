package handles

import (
	"strconv"

	"rho-aias/internal/blocklog"
	"rho-aias/internal/response"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// BlockLogHandle 阻断日志 API 处理器
type BlockLogHandle struct {
	blockLog *blocklog.BlockLog
}

// NewBlockLogHandle 创建新的阻断日志处理器
func NewBlockLogHandle(blockLog *blocklog.BlockLog) *BlockLogHandle {
	return &BlockLogHandle{
		blockLog: blockLog,
	}
}

// AttachStatsStore 注入统计存储（两阶段初始化：bizDB 就绪后调用）
func (h *BlockLogHandle) AttachStatsStore(db *gorm.DB) {
	if h.blockLog != nil {
		h.blockLog.AttachStatsStore(db)
	}
}

// GetRecords 获取阻断记录
// GET /api/blocklog/records?limit=100&match_type=ip4_exact&rule_source=manual
func (h *BlockLogHandle) GetRecords(c *gin.Context) {
	var filter blocklog.RecordFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		response.BadRequest(c, "Invalid query parameters: "+err.Error())
		return
	}

	// 默认限制为 100 条
	if filter.Limit == 0 {
		filter.Limit = 100
	}

	var records []blocklog.BlockRecord
	if filter.MatchType != "" || filter.RuleSource != "" || filter.SrcIP != "" || filter.CountryCode != "" {
		records = h.blockLog.GetRecordsByFilter(filter)
	} else {
		records = h.blockLog.GetRecords(filter.Limit)
	}

	response.OK(c, gin.H{
		"total":   len(records),
		"records": records,
	})
}

// GetStats 获取阻断统计
// GET /api/blocklog/stats
func (h *BlockLogHandle) GetStats(c *gin.Context) {
	stats := h.blockLog.GetStats()

	response.OK(c, stats)
}

// ClearRecords 清空阻断记录
// DELETE /api/blocklog/records
func (h *BlockLogHandle) ClearRecords(c *gin.Context) {
	h.blockLog.Clear()

	response.OKMsg(c, "Block log cleared")
}

// GetBlockedIPs 获取被阻断的 IP 列表（聚合）
// GET /api/blocklog/blocked-ips?limit=20
func (h *BlockLogHandle) GetBlockedIPs(c *gin.Context) {
	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := parseInt(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	stats := h.blockLog.GetStats()

	// 返回 Top N 被阻断的 IP
	topIPs := stats.TopBlockedIPs
	if len(topIPs) > limit {
		topIPs = topIPs[:limit]
	}

	response.OK(c, gin.H{
		"total_blocked_ips": len(stats.TopBlockedIPs),
		"top_blocked_ips":   topIPs,
	})
}

// GetBlockedCountries 获取被阻断的国家/地区列表
// GET /api/blocklog/blocked-countries?limit=20
func (h *BlockLogHandle) GetBlockedCountries(c *gin.Context) {
	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := parseInt(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	stats := h.blockLog.GetStats()

	// 返回 Top N 被阻断的国家
	topCountries := stats.TopBlockedCountries
	if len(topCountries) > limit {
		topCountries = topCountries[:limit]
	}

	response.OK(c, gin.H{
		"total_blocked_countries": len(stats.TopBlockedCountries),
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
		"hours":      hours,
		"hourly_data": trend,
	})
}

// GetDroppedSummary 获取丢弃概览
// GET /api/blocklog/dropped-summary?hours=168
func (h *BlockLogHandle) GetDroppedSummary(c *gin.Context) {
	hours := 168 // 默认查询最近 7 天
	if h := c.Query("hours"); h != "" {
		if parsed, err := parseInt(h); err == nil && parsed > 0 && parsed <= 8760 { // 最长 1 年
			hours = parsed
		}
	}

	summary := h.blockLog.GetDroppedSummary(hours)

	response.OK(c, gin.H{
		"hours":   hours,
		"total":   summary.Total,
		"sources": summary.Sources,
		"hourly":  summary.Hourly,
	})
}

func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}
