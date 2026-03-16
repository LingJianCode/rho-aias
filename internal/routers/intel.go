package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterIntelRoutes 注册情报路由
func RegisterIntelRoutes(group *gin.RouterGroup, intelHandle *handles.IntelHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	intel := group.Group("/intel")

	// 如果没有启用认证，直接注册路由
	if enforcer == nil || authService == nil || apiKeyService == nil {
		intel.GET("/status", intelHandle.GetStatus)
		intel.POST("/update", intelHandle.TriggerUpdate)
		return
	}

	// 启用认证，添加权限控制
	{
		// 查看情报状态 - 需要 intel:read 权限
		intel.GET("/status",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "intel:read", "read"),
			intelHandle.GetStatus,
		)

		// 触发更新 - 需要 intel:write 权限
		intel.POST("/update",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "intel:write", "write"),
			intelHandle.TriggerUpdate,
		)
	}
}
