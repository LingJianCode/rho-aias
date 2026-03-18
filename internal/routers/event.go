package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterEventRoutes 注册事件上报配置路由
func RegisterEventRoutes(group *gin.RouterGroup, eventHandle *handles.EventHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	events := group.Group("/xdp/events")

	// 如果没有启用认证，直接注册路由
	if enforcer == nil || authService == nil || apiKeyService == nil {
		events.GET("/status", eventHandle.GetEventStatus)
		events.POST("/config", eventHandle.SetEventConfig)
		return
	}

	// 启用认证，添加权限控制
	{
		// 获取事件状态 - 需要 firewall:read 权限
		events.GET("/status",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "firewall:read", "read"),
			eventHandle.GetEventStatus,
		)

		// 设置事件配置 - 需要 firewall:write 权限
		events.POST("/config",
			middleware.AuthMiddleware(authService, apiKeyService),
			middleware.CasbinMiddleware(enforcer, "firewall:write", "write"),
			eventHandle.SetEventConfig,
		)
	}
}
