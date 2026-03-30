package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"rho-aias/internal/auth/jwt"
	"rho-aias/internal/casbin"
	"rho-aias/internal/response"
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
	// ContextKeySubject Casbin Subject 上下文键
	ContextKeySubject = "sub"
	// ContextKeyAuthType 认证类型上下文键
	ContextKeyAuthType = "auth_type"
)

// AuthMiddleware 统一认证中间件（支持 JWT 和 API Key）
func AuthMiddleware(authService *services.AuthService, apiKeyService *services.APIKeyService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 尝试 API Key 认证
		apiKey := c.GetHeader("X-API-Key")
		if apiKey != "" {
			// 验证 API Key
			keyRecord, err := apiKeyService.ValidateAPIKey(apiKey)
			if err == nil {
				// API Key 认证成功
				c.Set(ContextKeyUserID, keyRecord.UserID)
				c.Set(ContextKeySubject, fmt.Sprintf("apikey:%s", keyRecord.Key))
				c.Set(ContextKeyAuthType, "api_key")
				c.Set(ContextKeyUserRole, "api_key") // API Key 没有角色概念
				c.Next()
				return
			}
			// API Key 无效，继续尝试 JWT
		}

		// 2. 尝试 JWT 认证
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.Unauthorized(c, "missing authorization")
			c.Abort()
			return
		}

		// 解析 Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			response.Unauthorized(c, "invalid authorization header format")
			c.Abort()
			return
		}

		tokenString := parts[1]

		// 验证 token
		claims, err := authService.ValidateToken(tokenString)
		if err != nil {
			if err == jwt.ErrExpiredToken {
				response.Fail(c, http.StatusUnauthorized, response.CodeTokenExpired, "token has expired")
			} else {
				response.Unauthorized(c, "invalid token")
			}
			c.Abort()
			return
		}

		// JWT 认证成功
		c.Set(ContextKeyUserID, claims.UserID)
		c.Set(ContextKeyUsername, claims.Username)
		c.Set(ContextKeyUserRole, claims.Role)
		c.Set(ContextKeySubject, fmt.Sprintf("user:%d", claims.UserID))
		c.Set(ContextKeyAuthType, "jwt")

		c.Next()
	}
}

// CasbinMiddleware Casbin 权限校验中间件
func CasbinMiddleware(enforcer *casbin.Enforcer, obj string, act string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从上下文获取 subject
		sub, exists := c.Get(ContextKeySubject)
		if !exists {
			response.Unauthorized(c, "unauthorized")
			c.Abort()
			return
		}

		// 执行权限校验
		allowed, err := enforcer.Enforce(sub, obj, act)
		if err != nil {
			response.InternalError(c, "failed to check permission")
			c.Abort()
			return
		}

		if !allowed {
			response.Forbidden(c, "permission denied")
			c.Abort()
			return
		}

		c.Next()
	}
}

// AdminMiddleware 管理员权限中间件
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get(ContextKeyUserRole)
		if !exists || role != "admin" {
			response.Fail(c, http.StatusForbidden, response.CodeAdminRequired, "admin access required")
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
