package routers

import (
	"rho-aias/internal/handles"

	"github.com/gin-gonic/gin"
)

// RegisterTcRoutes registers TC-related API routes
func RegisterTcRoutes(group *gin.RouterGroup, tcHandle *handles.TcHandle) {
	group.POST("/tc/rule", tcHandle.AddRule)
	group.DELETE("/tc/rule", tcHandle.DeleteRule)
	group.GET("/tc/rules", tcHandle.GetRules)
}
