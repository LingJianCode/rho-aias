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

	if enforcer == nil || authService == nil || apiKeyService == nil {
		banRecords.GET("", handle.GetBanRecords)
		banRecords.GET("/stats", handle.GetBanStats)
		banRecords.GET("/:id", handle.GetBanRecord)
		return
	}

	// 查询封禁记录 - 需要 ban_record:read 权限
	banRecords.GET("",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "ban_record:read", "read"),
		handle.GetBanRecords,
	)

	// 封禁统计 - 需要 ban_record:read 权限
	banRecords.GET("/stats",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "ban_record:read", "read"),
		handle.GetBanStats,
	)

	// 查询单条封禁记录 - 需要 ban_record:read 权限
	banRecords.GET("/:id",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "ban_record:read", "read"),
		handle.GetBanRecord,
	)
}
