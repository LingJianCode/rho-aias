package handles

import (
	"net/http"
	"time"

	"rho-aias/internal/geoblocking"
	"rho-aias/internal/logger"
	"rho-aias/internal/models"
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
	h.db.Raw("(?)", subQuery).Scan(&maxIDs)

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
	response := make(map[string]map[string]Result)
	for _, r := range results {
		if _, ok := response[r.SourceType]; !ok {
			response[r.SourceType] = make(map[string]Result)
		}
		response[r.SourceType][r.SourceID] = r
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "ok",
		"data":    response,
	})
}

// GetStatusByType 获取指定类型的数据源状态
func (h *SourceHandle) GetStatusByType(c *gin.Context) {
	sourceType := c.Param("type")
	if sourceType == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "source_type is required",
		})
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
	h.db.Raw("(?)", subQuery).Scan(&maxIDs)

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
	response := make(map[string]models.SourceStatusRecord)
	for _, r := range records {
		response[r.SourceID] = r
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "ok",
		"data":    response,
	})
}

// GetStatusByID 获取指定数据源的状态
func (h *SourceHandle) GetStatusByID(c *gin.Context) {
	sourceType := c.Param("type")
	sourceID := c.Param("id")

	if sourceType == "" || sourceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "source_type and source_id are required",
		})
		return
	}

	// 获取该数据源最新的记录
	var record models.SourceStatusRecord
	err := h.db.Where("source_type = ? AND source_id = ?", sourceType, sourceID).
		Order("id DESC").
		First(&record).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"code":    404,
				"message": "source status not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    500,
				"message": "database error: " + err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "ok",
		"data":    record,
	})
}

// Refresh 手动触发数据源更新
func (h *SourceHandle) Refresh(c *gin.Context) {
	sourceType := c.Param("type")
	sourceID := c.Param("id")

	if sourceType == "" || sourceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "source_type and source_id are required",
		})
		return
	}

	logger.Infof("[API] Manual refresh triggered for %s/%s", sourceType, sourceID)

	// 根据类型触发相应的更新
	var err error
	switch sourceType {
	case "intel":
		if h.intelMgr == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"code":    503,
				"message": "Intel manager is not initialized",
			})
			return
		}
		err = h.intelMgr.TriggerUpdate()
	case "geo_blocking":
		if h.geoMgr == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"code":    503,
				"message": "Geo-blocking manager is not initialized",
			})
			return
		}
		err = h.geoMgr.TriggerUpdate()
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "Invalid source_type: " + sourceType,
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "Refresh failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "Refresh triggered successfully",
	})
}
