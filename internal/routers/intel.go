package routers

import (
	"rho-aias/internal/handles"

	"github.com/gin-gonic/gin"
)

// RegisterIntelRoutes 注册情报路由
func RegisterIntelRoutes(group *gin.RouterGroup, intelHandle *handles.IntelHandle) {
	intel := group.Group("/intel")
	{
		intel.GET("/status", intelHandle.GetStatus)
		intel.POST("/update", intelHandle.TriggerUpdate)
	}
}
