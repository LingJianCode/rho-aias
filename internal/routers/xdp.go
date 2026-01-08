package routers

import (
	"rho-aias/internal/handles"

	"github.com/gin-gonic/gin"
)

// RegisterXdpRoutes 注册 XDP 路由
func RegisterXdpRoutes(group *gin.RouterGroup, xdpHandle *handles.XdpHandle) {
	group.GET("/rule", xdpHandle.GetRule)
	group.POST("/rule", xdpHandle.AddRule)
	group.DELETE("/rule", xdpHandle.DelRule)
}
