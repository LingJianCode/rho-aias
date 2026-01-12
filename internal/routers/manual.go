package routers

import (
	"rho-aias/internal/handles"

	"github.com/gin-gonic/gin"
)

// RegisterManualRoutes 注册手动规则管理路由
func RegisterManualRoutes(group *gin.RouterGroup, manualHandle *handles.ManualHandle) {
	manual := group.Group("/manual")
	{
		manual.GET("/rules", manualHandle.GetRule)
		manual.POST("/rules", manualHandle.AddRule)
		manual.DELETE("/rules", manualHandle.DelRule)
	}
}
