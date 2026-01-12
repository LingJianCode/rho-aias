package routers

import (
	"rho-aias/internal/handles"

	"github.com/gin-gonic/gin"
)

// RegisterGeoBlockingRoutes 注册 Geo-Blocking 路由
func RegisterGeoBlockingRoutes(group *gin.RouterGroup, geoHandle *handles.GeoBlockingHandle) {
	geo := group.Group("/geoblocking")
	{
		geo.GET("/status", geoHandle.GetStatus)
		geo.POST("/update", geoHandle.TriggerUpdate)
		geo.POST("/config", geoHandle.UpdateConfig)
	}
}
