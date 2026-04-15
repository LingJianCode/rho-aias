package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterManualRoutes 注册手动规则管理路由（黑名单）
// 路由路径: /api/manual/blacklist/rules
func RegisterManualRoutes(group *gin.RouterGroup, manualHandle *handles.ManualHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	manual := group.Group("/manual")

	blacklist := manual.Group("/blacklist")

	// 添加黑名单规则 - 需要 firewall:write 权限
	blacklist.POST("/rules",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "firewall", "write"),
		manualHandle.AddRule,
	)

	// 删除黑名单规则 - 需要 firewall:write 权限
	blacklist.DELETE("/rules",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "firewall", "write"),
		manualHandle.DelRule,
	)

	// 查询黑名单规则列表 - 需要 firewall:read 权限
	blacklist.GET("/rules",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "firewall", "read"),
		manualHandle.ListManualRules,
	)
}

// RegisterWhitelistRoutes 注册白名单管理路由
// 路由路径: /api/manual/whitelist/rules
func RegisterWhitelistRoutes(group *gin.RouterGroup, whitelistHandle *handles.WhitelistHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	manual := group.Group("/manual")

	whitelist := manual.Group("/whitelist")

	// 添加白名单规则 - 需要 firewall:write 权限
	whitelist.POST("/rules",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "firewall", "write"),
		whitelistHandle.AddWhitelistRule,
	)

	// 删除白名单规则 - 需要 firewall:write 权限
	whitelist.DELETE("/rules",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "firewall", "write"),
		whitelistHandle.DelWhitelistRule,
	)

	// 查询白名单规则列表 - 需要 firewall:read 权限
	whitelist.GET("/rules",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "firewall", "read"),
		whitelistHandle.ListWhitelistRules,
	)
}
