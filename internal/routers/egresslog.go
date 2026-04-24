package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterEgressLogRoutes 注册 Egress 丢包日志路由
func RegisterEgressLogRoutes(group *gin.RouterGroup, egressLogHandle *handles.EgressLogHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	egresslog := group.Group("/egresslog")

	// 查看丢包记录 - 需要 egresslog:read 权限
	egresslog.GET("/records",
		middleware.AuthMiddleware(authService, apiKeyService),
		middleware.CasbinMiddleware(enforcer, "egresslog", "read"),
		egressLogHandle.GetRecords,
	)
}
