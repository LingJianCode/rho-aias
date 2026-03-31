package handles

import (
	"net/http"
	"time"

	"rho-aias/internal/geoblocking"
	"rho-aias/internal/logger"
	"rho-aias/internal/models"
	"rho-aias/internal/response"
	"rho-aias/internal/threatintel"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// SourceHandle 数据源状态 API 处理器
type SourceHandle struct {
	db        *gorm.DB
	intelMgr  *threatintel.Manager
	geoMgr    *geoblocking.Manager
}

// NewSourceHandle 创建新的数据源状态处理器
func NewSourceHandle(db *gorm.DB, intelMgr *threatintel.Manager, geoMgr *geoblocking.Manager) *SourceHandle {
	return &SourceHandle{
		db:       db,
		intelMgr: intelMgr,
		geoMgr:   geoMgr,
	}
}

// GetStatus 获取所有数据源状态
func (h *SourceHandle) GetStatus(c *gin.Context) {
	// 获取最近一次的状态记录（每个数据源只保留最新的）
	type Result struct {
		ID           uint      `json:"id"`
		SourceType   string    `json:"source_type"`
		SourceID     string    `json:"source_id"`
		SourceName   string    `json:"source_name"`
		Status       string    `json:"status"`
		RuleCount    int       `json:"rule_count"`
		ErrorMessage string    `json:"error_message"`
		Duration     int       `json:"duration"`
		UpdatedAt    time.Time `json:"updated_at"`
	}

	// 使用子查询获取每个数据源最新的记录
	subQuery := h.db.Model(&models.SourceStatusRecord{}).
		Select("MAX(id) as max_id").
		Group("source_type, source_id")

	var maxIDs []struct {
		MaxID uint
	}
	subQuery.Scan(&maxIDs)

	// 获取最新记录
	var results []Result
	var ids []uint
	for _, item := range maxIDs {
		ids = append(ids, item.MaxID)
	}

	if len(ids) > 0 {
		h.db.Model(&models.SourceStatusRecord{}).
			Where("id IN ?", ids).
			Order("source_type, source_id").
			Find(&results)
	}

	// 按类型组织数据
	resp := make(map[string]map[string]Result)
	for _, r := range results {
		if _, ok := resp[r.SourceType]; !ok {
			resp[r.SourceType] = make(map[string]Result)
		}
		resp[r.SourceType][r.SourceID] = r
	}

	response.OK(c, resp)
}

// GetStatusByType 获取指定类型的数据源状态
func (h *SourceHandle) GetStatusByType(c *gin.Context) {
	sourceType := c.Param("type")
	if sourceType == "" {
		response.BadRequest(c, "source_type is required")
		return
	}

	var records []models.SourceStatusRecord

	// 获取该类型每个数据源的最新记录
	subQuery := h.db.Model(&models.SourceStatusRecord{}).
		Select("MAX(id) as max_id").
		Where("source_type = ?", sourceType).
		Group("source_id")

	var maxIDs []struct {
		MaxID uint
	}
	subQuery.Scan(&maxIDs)

	// 获取最新记录
	if len(maxIDs) > 0 {
		var ids []uint
		for _, item := range maxIDs {
			ids = append(ids, item.MaxID)
		}

		h.db.Model(&models.SourceStatusRecord{}).
			Where("id IN ?", ids).
			Order("source_id").
			Find(&records)
	}

	// 按数据源 ID 组织数据
	resp := make(map[string]models.SourceStatusRecord)
	for _, r := range records {
		resp[r.SourceID] = r
	}

	response.OK(c, resp)
}

// GetStatusByID 获取指定数据源的状态
func (h *SourceHandle) GetStatusByID(c *gin.Context) {
	sourceType := c.Param("type")
	sourceID := c.Param("id")

	if sourceType == "" || sourceID == "" {
		response.BadRequest(c, "source_type and source_id are required")
		return
	}

	// 获取该数据源最新的记录
	var record models.SourceStatusRecord
	err := h.db.Where("source_type = ? AND source_id = ?", sourceType, sourceID).
		Order("id DESC").
		First(&record).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			response.Fail(c, http.StatusNotFound, response.CodeSourceNotFound, "source status not found")
		} else {
			response.InternalError(c, "database error: "+err.Error())
		}
		return
	}

	response.OK(c, record)
}

// Refresh 手动触发数据源更新
func (h *SourceHandle) Refresh(c *gin.Context) {
	sourceType := c.Param("type")
	sourceID := c.Param("id")

	if sourceType == "" || sourceID == "" {
		response.BadRequest(c, "source_type and source_id are required")
		return
	}

	logger.Infof("[API] Manual refresh triggered for %s/%s", sourceType, sourceID)

	// 根据类型触发相应的更新
	var err error
	switch sourceType {
	case "intel":
		if h.intelMgr == nil {
			response.Fail(c, http.StatusServiceUnavailable, response.CodeInternal, "Intel manager is not initialized")
			return
		}
		err = h.intelMgr.TriggerUpdate()
	case "geo_blocking":
		if h.geoMgr == nil {
			response.Fail(c, http.StatusServiceUnavailable, response.CodeInternal, "Geo-blocking manager is not initialized")
			return
		}
		err = h.geoMgr.TriggerUpdate()
	default:
		response.BadRequest(c, "Invalid source_type: "+sourceType)
		return
	}

	if err != nil {
		response.InternalError(c, "Refresh failed: "+err.Error())
		return
	}

	response.OKMsg(c, "Refresh triggered successfully")
}
