package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterConfigRoutes 注册统一配置路由
func RegisterConfigRoutes(group *gin.RouterGroup, configHandle *handles.ConfigHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	config := group.Group("/config")

	// 获取所有模块配置 - 需要 config:read 权限
	config.GET("",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "config:read", "read"),
		configHandle.GetAllConfig,
	)

	// 获取指定模块配置 - 需要 config:read 权限
	config.GET("/:module",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "config:read", "read"),
		configHandle.GetModuleConfig,
	)

	// 更新指定模块配置 - 需要 config:write 权限
	config.PUT("/:module",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "config:write", "write"),
		configHandle.UpdateModuleConfig,
	)
}
