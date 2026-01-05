package routers

import (
	"rho-aias/internal/handles"

	"github.com/gin-gonic/gin"
)

func RegisterXdpRoutes(group *gin.RouterGroup, xdpHandle *handles.XdpHandle) {
	group.GET("/rule", xdpHandle.GetRule)
	group.POST("/rule", xdpHandle.AddRule)
}
