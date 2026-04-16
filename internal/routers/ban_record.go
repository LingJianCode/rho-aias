package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterBanRecordRoutes 注册封禁记录路由
func RegisterBanRecordRoutes(group *gin.RouterGroup, handle *handles.BanRecordHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	banRecords := group.Group("/ban-records")

	// 查询封禁记录 - 需要 ban_record:read 权限
	banRecords.GET("",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "ban_record", "read"),
		handle.GetBanRecords,
	)

	// 封禁统计 - 需要 ban_record:read 权限
	banRecords.GET("/stats",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "ban_record", "read"),
		handle.GetBanStats,
	)

	// 查询单条封禁记录 - 需要 ban_record:read 权限
	banRecords.GET("/:id",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "ban_record", "read"),
		handle.GetBanRecord,
	)

	// 解封封禁记录 - 需要 ban_record:write 权限
	banRecords.DELETE("/:id/unblock",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "ban_record", "write"),
		handle.UnbanBanRecord,
	)
}
