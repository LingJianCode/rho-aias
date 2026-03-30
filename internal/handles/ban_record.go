package handles

import (
	"net/http"
	"strconv"

	"rho-aias/internal/models"
	"rho-aias/internal/response"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// BanRecordHandle 封禁记录 API 处理器
type BanRecordHandle struct {
	service *services.BanRecordService
}

// NewBanRecordHandle 创建封禁记录处理器
func NewBanRecordHandle(service *services.BanRecordService) *BanRecordHandle {
	return &BanRecordHandle{service: service}
}

// GetBanRecords 查询封禁记录
// GET /api/ban-records?ip=x.x.x.x&source=waf&status=active&limit=50&offset=0&order_by=created_at&order=desc
func (h *BanRecordHandle) GetBanRecords(c *gin.Context) {
	var filter services.BanRecordFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		response.BadRequest(c, "Invalid query parameters: "+err.Error())
		return
	}

	records, total, err := h.service.QueryRecords(filter)
	if err != nil {
		response.InternalError(c, "Failed to query ban records: "+err.Error())
		return
	}

	response.OK(c, gin.H{
		"total":   total,
		"limit":   filter.Limit,
		"offset":  filter.Offset,
		"records": records,
	})
}

// GetBanStats 获取封禁统计
// GET /api/ban-records/stats
func (h *BanRecordHandle) GetBanStats(c *gin.Context) {
	stats, err := h.service.GetBanStats()
	if err != nil {
		response.InternalError(c, "Failed to get ban stats: "+err.Error())
		return
	}

	response.OK(c, stats)
}

// GetBanRecord 查询单条封禁记录
// GET /api/ban-records/:id
func (h *BanRecordHandle) GetBanRecord(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		response.BadRequest(c, "Invalid record ID")
		return
	}

	record := &models.BanRecord{}
	if err := h.service.DB().First(record, uint(id)).Error; err != nil {
		response.Fail(c, http.StatusNotFound, response.CodeRecordNotFound, "Ban record not found")
		return
	}

	response.OK(c, record)
}
