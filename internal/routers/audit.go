package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterAuditRoutes 注册审计日志路由
func RegisterAuditRoutes(group *gin.RouterGroup, auditHandle *handles.AuditHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	audit := group.Group("/audit")
	{
		// 所有接口都需要认证
		audit.Use(middleware.AuthMiddleware(authService, apiKeyService))

		// 列出审计日志 - 需要 admin:* 权限
		audit.GET("/logs", middleware.CasbinMiddleware(enforcer, "admin:*", "*"), auditHandle.ListAuditLogs)

		// 获取单条日志 - 需要 admin:* 权限
		audit.GET("/logs/:id", middleware.CasbinMiddleware(enforcer, "admin:*", "*"), auditHandle.GetAuditLog)

		// 清理旧日志 - 需要 admin:* 权限
		audit.POST("/clean", middleware.CasbinMiddleware(enforcer, "admin:*", "*"), auditHandle.CleanAuditLogs)
	}
}
