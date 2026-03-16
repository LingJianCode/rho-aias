package handles

import (
	"net/http"
	"strconv"

	"rho-aias/internal/middleware"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// APIKeyHandle API Key 处理器
type APIKeyHandle struct {
	apiKeyService *services.APIKeyService
}

// NewAPIKeyHandle 创建 API Key 处理器
func NewAPIKeyHandle(apiKeyService *services.APIKeyService) *APIKeyHandle {
	return &APIKeyHandle{
		apiKeyService: apiKeyService,
	}
}

// CreateAPIKey 创建 API Key
func (h *APIKeyHandle) CreateAPIKey(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

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

	c.JSON(http.StatusOK, gin.H{"message": "api key revoked successfully"})
}
