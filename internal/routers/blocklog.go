package routers

import (
	"rho-aias/internal/handles"

	"github.com/gin-gonic/gin"
)

// RegisterBlockLogRoutes 注册阻断日志路由
func RegisterBlockLogRoutes(group *gin.RouterGroup, blockLogHandle *handles.BlockLogHandle) {
	blocklog := group.Group("/blocklog")
	{
		blocklog.GET("/records", blockLogHandle.GetRecords)
		blocklog.GET("/stats", blockLogHandle.GetStats)
		blocklog.GET("/blocked-ips", blockLogHandle.GetBlockedIPs)
		blocklog.GET("/blocked-countries", blockLogHandle.GetBlockedCountries)
		blocklog.DELETE("/records", blockLogHandle.ClearRecords)
	}
}
