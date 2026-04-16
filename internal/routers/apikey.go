package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterAPIKeyRoutes 注册 API Key 管理路由
func RegisterAPIKeyRoutes(group *gin.RouterGroup, apiKeyHandle *handles.APIKeyHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	apikeys := group.Group("/api-keys")
	{
		// 所有接口都需要认证
		apikeys.Use(middleware.AuthMiddleware(authService, apiKeyService))

		// 创建 API Key - 需要 api_key:write 权限
		apikeys.POST("", middleware.CasbinMiddleware(enforcer, "api_key", "write"), apiKeyHandle.CreateAPIKey)

		// 列出 API Keys - 需要 api_key:read 权限
		apikeys.GET("", middleware.CasbinMiddleware(enforcer, "api_key", "read"), apiKeyHandle.ListAPIKeys)

		// 吊销 API Key - 需要 api_key:write 权限
		apikeys.DELETE("/:id", middleware.CasbinMiddleware(enforcer, "api_key", "write"), apiKeyHandle.RevokeAPIKey)

		// 获取可用权限列表（公开给已认证用户）
		apikeys.GET("/permissions", apiKeyHandle.GetPermissions)
	}
}
