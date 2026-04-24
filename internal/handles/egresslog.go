package handles

import (
	"time"

	"rho-aias/internal/ebpfs"
	"rho-aias/internal/egresslog"
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
