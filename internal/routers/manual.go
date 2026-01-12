package routers

import (
	"rho-aias/internal/handles"

	"github.com/gin-gonic/gin"
)

// RegisterManualRoutes 注册手动规则管理路由
func RegisterManualRoutes(group *gin.RouterGroup, manualHandle *handles.ManualHandle) {
	group.GET("/rule", manualHandle.GetRule)
	group.POST("/rule", manualHandle.AddRule)
	group.DELETE("/rule", manualHandle.DelRule)
}
