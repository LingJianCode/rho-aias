package handles

import (
	"net/http"
	"strconv"

	"rho-aias/internal/ebpfs"
	"rho-aias/internal/models"
	"rho-aias/internal/response"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// BanRecordHandle 封禁记录 API 处理器
type BanRecordHandle struct {
	service *services.BanRecordService
	xdp     *ebpfs.Xdp
}

// NewBanRecordHandle 创建封禁记录处理器
func NewBanRecordHandle(service *services.BanRecordService, xdp *ebpfs.Xdp) *BanRecordHandle {
	return &BanRecordHandle{service: service, xdp: xdp}
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

// UnbanBanRecord 手动解封封禁记录
// DELETE /api/ban-records/:id/unblock
func (h *BanRecordHandle) UnbanBanRecord(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		response.BadRequest(c, "Invalid record ID")
		return
	}

	// 获取封禁记录
	record, err := h.service.GetRecordByID(uint(id))
	if err != nil {
		response.Fail(c, http.StatusNotFound, response.CodeRecordNotFound, "Ban record not found")
		return
	}

	// 检查状态是否为 active
	if record.Status != models.BanStatusActive {
		response.BadRequest(c, "Ban record is not in active status")
		return
	}

	// 从 eBPF map 移除对应来源的规则
	sourceMask, ok := ebpfs.SourceStringToMask(record.Source)
	if ok && h.xdp != nil {
		_, _, _, err := h.xdp.UpdateRuleSourceMask(record.IP, sourceMask)
		if err != nil {
			response.InternalError(c, "Failed to remove IP from eBPF map: "+err.Error())
			return
		}
		// 注意：即使 eBPF map 中不存在该规则，也继续更新数据库状态
	}

	// 更新数据库状态为手动解封
	if err := h.service.UpdateStatusByID(uint(id), models.BanStatusManualUnblock); err != nil {
		response.InternalError(c, "Failed to update ban record status: "+err.Error())
		return
	}

	response.OK(c, gin.H{
		"message": "IP unblocked successfully",
		"ip":      record.IP,
		"source":  record.Source,
	})
}
