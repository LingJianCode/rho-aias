package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterManualRoutes 注册手动规则管理路由
func RegisterManualRoutes(group *gin.RouterGroup, manualHandle *handles.ManualHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	manual := group.Group("/manual")

	// 如果没有启用认证，直接注册路由
	if enforcer == nil || authService == nil || apiKeyService == nil {
		manual.GET("/rules", manualHandle.GetRule)
		manual.POST("/rules", manualHandle.AddRule)
		manual.DELETE("/rules", manualHandle.DelRule)
		return
	}

	// 启用认证，添加权限控制
	{
		// 查看规则 - 需要 firewall:read 权限
		manual.GET("/rules",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "firewall:read", "read"),
			manualHandle.GetRule,
		)

		// 添加规则 - 需要 firewall:write 权限
		manual.POST("/rules",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "firewall:write", "write"),
			manualHandle.AddRule,
		)

		// 删除规则 - 需要 firewall:write 权限
		manual.DELETE("/rules",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "firewall:write", "write"),
			manualHandle.DelRule,
		)
	}
}
