package handles

import (
	"strconv"

	"rho-aias/internal/blocklog"
	"rho-aias/internal/response"

	"github.com/gin-gonic/gin"
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

func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}
