package routers

import (
	"rho-aias/internal/handles"

	"github.com/gin-gonic/gin"
)

// RegisterGeoBlockingRoutes 注册 Geo-Blocking 路由
func RegisterGeoBlockingRoutes(group *gin.RouterGroup, geoHandle *handles.GeoBlockingHandle) {
	group.GET("/status", geoHandle.GetStatus)
	group.POST("/update", geoHandle.TriggerUpdate)
	group.POST("/config", geoHandle.UpdateConfig)
}
