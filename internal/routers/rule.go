package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterRuleRoutes 注册规则查询路由
func RegisterRuleRoutes(group *gin.RouterGroup, ruleQueryHandle *handles.RuleQueryHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	rules := group.Group("/rules")

	// 查询规则 - 需要 firewall:read 权限
	rules.GET("",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "firewall:read", "read"),
		ruleQueryHandle.GetRules,
	)
}
