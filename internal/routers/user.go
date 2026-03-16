package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterUserRoutes 注册用户管理路由
func RegisterUserRoutes(group *gin.RouterGroup, userHandle *handles.UserHandle, enforcer *casbin.Enforcer, authService *services.AuthService, apiKeyService *services.APIKeyService) {
	users := group.Group("/users")
	{
		// 所有接口都需要认证
		users.Use(middleware.AuthMiddleware(authService, apiKeyService))

		// 创建用户 - 需要 admin:* 权限
		users.POST("", middleware.CasbinMiddleware(enforcer, "admin:*", "*"), userHandle.CreateUser)

		// 列出用户 - 需要 admin:* 权限
		users.GET("", middleware.CasbinMiddleware(enforcer, "admin:*", "*"), userHandle.ListUsers)

		// 获取用户详情 - 需要 admin:* 权限
		users.GET("/:id", middleware.CasbinMiddleware(enforcer, "admin:*", "*"), userHandle.GetUser)

		// 更新用户 - 需要 admin:* 权限
		users.PUT("/:id", middleware.CasbinMiddleware(enforcer, "admin:*", "*"), userHandle.UpdateUser)

		// 删除用户 - 需要 admin:* 权限
		users.DELETE("/:id", middleware.CasbinMiddleware(enforcer, "admin:*", "*"), userHandle.DeleteUser)
	}
}
