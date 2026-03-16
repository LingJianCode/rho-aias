package routers

import (
	"rho-aias/internal/casbin"
	"rho-aias/internal/handles"
	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// RegisterAuthRoutes 注册认证路由
func RegisterAuthRoutes(group *gin.RouterGroup, authHandle *handles.AuthHandle, authService *services.AuthService, apiKeyService *services.APIKeyService, enforcer *casbin.Enforcer) {
	auth := group.Group("/auth")
	{
		// 公开路由（无需认证）
		auth.GET("/captcha", authHandle.GetCaptcha)
		auth.POST("/login", authHandle.Login)
		auth.POST("/refresh", authHandle.RefreshToken)
		auth.POST("/logout", authHandle.Logout)

		// 需要认证的路由
		protected := auth.Group("")
		protected.Use(middleware.AuthMiddleware(authService, apiKeyService))
		{
			protected.GET("/me", authHandle.GetCurrentUser)
			protected.PUT("/password", authHandle.ChangePassword)
		}
	}
}
