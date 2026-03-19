package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterSourceRoutes 注册数据源状态路由
func RegisterSourceRoutes(group *gin.RouterGroup, sourceHandle *handles.SourceHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	source := group.Group("/sources")

	// 如果没有启用认证，直接注册路由
	if enforcer == nil || authService == nil || apiKeyService == nil {
		source.GET("/status", sourceHandle.GetStatus)
		source.GET("/:type/status", sourceHandle.GetStatusByType)
		source.GET("/:type/:id/status", sourceHandle.GetStatusByID)
		source.POST("/:type/:id/refresh", sourceHandle.Refresh)
		return
	}

	// 启用认证，添加权限控制
	{
		// 获取所有数据源状态 - 需要 source:read 权限
		source.GET("/status",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "source:read", "read"),
			sourceHandle.GetStatus,
		)

		// 获取指定类型的数据源状态 - 需要 source:read 权限
		source.GET("/:type/status",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "source:read", "read"),
			sourceHandle.GetStatusByType,
		)

		// 获取指定数据源的状态 - 需要 source:read 权限
		source.GET("/:type/:id/status",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "source:read", "read"),
			sourceHandle.GetStatusByID,
		)

		// 手动触发数据源更新 - 需要 source:write 权限
		source.POST("/:type/:id/refresh",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "source:write", "write"),
			sourceHandle.Refresh,
		)
	}
}
