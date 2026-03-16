package middleware

import (
	"net/http"
	"strings"

	"rho-aias/internal/auth/jwt"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

const (
	// ContextKeyUserID 用户 ID 上下文键
	ContextKeyUserID = "user_id"
	// ContextKeyUsername 用户名上下文键
	ContextKeyUsername = "username"
	// ContextKeyUserRole 用户角色上下文键
	ContextKeyUserRole = "user_role"
)

// AuthMiddleware JWT 认证中间件
func AuthMiddleware(authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 Header 获取 token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			c.Abort()
			return
		}

		// 解析 Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// 验证 token
		claims, err := authService.ValidateToken(tokenString)
		if err != nil {
			if err == jwt.ErrExpiredToken {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "token has expired",
					"code":  "TOKEN_EXPIRED",
				})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "invalid token",
				})
			}
			c.Abort()
			return
		}

		// 将用户信息存入上下文
		c.Set(ContextKeyUserID, claims.UserID)
		c.Set(ContextKeyUsername, claims.Username)
		c.Set(ContextKeyUserRole, claims.Role)

		c.Next()
	}
}

// AdminMiddleware 管理员权限中间件
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get(ContextKeyUserRole)
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "admin access required",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// GetUserID 从上下文获取用户 ID
func GetUserID(c *gin.Context) (uint, bool) {
	userID, exists := c.Get(ContextKeyUserID)
	if !exists {
		return 0, false
	}
	return userID.(uint), true
}

// GetUsername 从上下文获取用户名
func GetUsername(c *gin.Context) (string, bool) {
	username, exists := c.Get(ContextKeyUsername)
	if !exists {
		return "", false
	}
	return username.(string), true
}

// GetUserRole 从上下文获取用户角色
func GetUserRole(c *gin.Context) (string, bool) {
	role, exists := c.Get(ContextKeyUserRole)
	if !exists {
		return "", false
	}
	return role.(string), true
}
