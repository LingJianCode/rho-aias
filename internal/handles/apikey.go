package handles

import (
	"encoding/json"
	"net/http"
	"strconv"

	"rho-aias/internal/middleware"
	"rho-aias/internal/models"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// APIKeyHandle API Key 处理器
type APIKeyHandle struct {
	apiKeyService *services.APIKeyService
	auditService  *services.AuditService
}

// NewAPIKeyHandle 创建 API Key 处理器
func NewAPIKeyHandle(apiKeyService *services.APIKeyService, auditService *services.AuditService) *APIKeyHandle {
	return &APIKeyHandle{
		apiKeyService: apiKeyService,
		auditService:  auditService,
	}
}

// CreateAPIKey 创建 API Key
func (h *APIKeyHandle) CreateAPIKey(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	username, _ := middleware.GetUsername(c)

	var req services.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.apiKeyService.CreateAPIKey(userID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 记录审计日志
	detail, _ := json.Marshal(map[string]interface{}{
		"name":        resp.Name,
		"permissions": resp.Permissions,
	})
	_ = h.auditService.Log(services.LogRequest{
		UserID:     userID,
		Username:   username,
		Action:     models.ActionCreateAPIKey,
		Resource:   models.ResourceAPIKey,
		ResourceID: strconv.FormatUint(uint64(resp.ID), 10),
		Detail:     string(detail),
		IP:         c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	})

	c.JSON(http.StatusCreated, resp)
}

// ListAPIKeys 列出 API Keys
func (h *APIKeyHandle) ListAPIKeys(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	keys, err := h.apiKeyService.ListAPIKeys(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

// RevokeAPIKey 吊销 API Key
func (h *APIKeyHandle) RevokeAPIKey(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	username, _ := middleware.GetUsername(c)

	keyIDStr := c.Param("id")
	keyID, err := strconv.ParseUint(keyIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key id"})
		return
	}

	if err := h.apiKeyService.RevokeAPIKey(userID, uint(keyID)); err != nil {
		if err.Error() == "api key not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// 记录审计日志
	_ = h.auditService.Log(services.LogRequest{
		UserID:     userID,
		Username:   username,
		Action:     models.ActionRevokeAPIKey,
		Resource:   models.ResourceAPIKey,
		ResourceID: keyIDStr,
		IP:         c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	})

	c.JSON(http.StatusOK, gin.H{"message": "api key revoked successfully"})
}
