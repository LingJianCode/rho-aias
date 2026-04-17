package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterBlockLogRoutes 注册阻断日志路由
func RegisterBlockLogRoutes(group *gin.RouterGroup, blockLogHandle *handles.BlockLogHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	blocklog := group.Group("/blocklog")

	// 查看阻断记录 - 需要 blocklog:read 权限
	blocklog.GET("/records",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "blocklog", "read"),
		blockLogHandle.GetRecords,
	)

	// 查看统计数据 - 需要 blocklog:read 权限
	blocklog.GET("/stats",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "blocklog", "read"),
		blockLogHandle.GetStats,
	)

	// 查看阻断 IP 列表 - 需要 blocklog:read 权限
	blocklog.GET("/blocked-top-ips",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "blocklog", "read"),
		blockLogHandle.GetBlockedTopIPs,
	)

	// 查看阻断国家列表 - 需要 blocklog:read 权限
	blocklog.GET("/blocked-countries",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "blocklog", "read"),
		blockLogHandle.GetBlockedCountries,
	)

	// 查看小时趋势 - 需要 blocklog:read 权限
	blocklog.GET("/hourly-trend",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "blocklog", "read"),
		blockLogHandle.GetHourlyTrend,
	)

	// 查看阻断事件上报状态 - 需要 blocklog:read 权限
	blocklog.GET("/event-status",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "blocklog", "read"),
		blockLogHandle.GetEventStatus,
	)
}
