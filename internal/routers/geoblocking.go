package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterGeoBlockingRoutes 注册 Geo-Blocking 路由
func RegisterGeoBlockingRoutes(group *gin.RouterGroup, geoHandle *handles.GeoBlockingHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	geo := group.Group("/geoblocking")

	// 如果没有启用认证，直接注册路由
	if enforcer == nil || authService == nil || apiKeyService == nil {
		geo.GET("/status", geoHandle.GetStatus)
		geo.POST("/update", geoHandle.TriggerUpdate)
		geo.POST("/config", geoHandle.UpdateConfig)
		return
	}

	// 启用认证，添加权限控制
	{
		// 查看状态 - 需要 geo:read 权限
		geo.GET("/status",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "geo:read", "read"),
			geoHandle.GetStatus,
		)

		// 触发更新 - 需要 geo:write 权限
		geo.POST("/update",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "geo:write", "write"),
			geoHandle.TriggerUpdate,
		)

		// 更新配置 - 需要 geo:write 权限
		geo.POST("/config",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "geo:write", "write"),
			geoHandle.UpdateConfig,
		)
	}
}
