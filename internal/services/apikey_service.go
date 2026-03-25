package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"rho-aias/internal/auth/apikey"
	"rho-aias/internal/casbin"
	"rho-aias/internal/models"

	"gorm.io/gorm"
)

// ValidPermissions 定义有效的权限白名单
var ValidPermissions = map[string]bool{
	"firewall:read":  true,
	"firewall:write": true,
	"intel:read":     true,
	"intel:write":    true,
	"geo:read":       true,
	"geo:write":      true,
	"blocklog:read":  true,
	"blocklog:clear": true,
	"api_key:manage": true,
	"admin:*":        true,
}

var (
	// ErrAPIKeyNotFound API Key 不存在错误
	ErrAPIKeyNotFound = errors.New("api key not found")
)

// APIKeyService API Key 服务
type APIKeyService struct {
	db       *gorm.DB
	enforcer *casbin.Enforcer
}

// NewAPIKeyService 创建 API Key 服务
func NewAPIKeyService(db *gorm.DB, enforcer *casbin.Enforcer) *APIKeyService {
	return &APIKeyService{
		db:       db,
		enforcer: enforcer,
	}
}

// CreateAPIKeyRequest 创建 API Key 请求
type CreateAPIKeyRequest struct {
	Name        string   `json:"name" binding:"required"`
	Permissions []string `json:"permissions" binding:"required"`
	ExpiresDays int      `json:"expires_days"` // 0 表示永久
}

// CreateAPIKeyResponse 创建 API Key 响应
type CreateAPIKeyResponse struct {
	ID          uint     `json:"id"`
	Name        string   `json:"name"`
	Key         string   `json:"key"` // 仅在创建时返回明文
	Permissions []string `json:"permissions"`
	ExpiresAt   *string  `json:"expires_at"`
	CreatedAt   string   `json:"created_at"`
}

// CreateAPIKey 创建 API Key
func (s *APIKeyService) CreateAPIKey(userID uint, req CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	// 验证权限有效性
	for _, perm := range req.Permissions {
		if !ValidPermissions[perm] {
			return nil, fmt.Errorf("invalid permission: %s", perm)
		}
	}

	// 生成 Key
	key, hash, err := apikey.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	// 序列化权限
	permissionsJSON, err := json.Marshal(req.Permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal permissions: %w", err)
	}

	// 构造响应函数（用于事务内构造）
	var response *CreateAPIKeyResponse

	// 使用事务保证原子性
	err = s.db.Transaction(func(tx *gorm.DB) error {
		// 创建数据库记录
		apiKeyRecord := &models.APIKey{
			Name:        req.Name,
			Key:         hash,
			KeyPrefix:   key[:16], // 保存前缀用于显示
			UserID:      userID,
			Permissions: string(permissionsJSON),
			Active:      true,
		}

		// 设置过期时间
		if req.ExpiresDays > 0 {
			expiresAt := time.Now().AddDate(0, 0, req.ExpiresDays)
			apiKeyRecord.ExpiresAt = &expiresAt
		}

		// 保存到数据库
		if err := tx.Create(apiKeyRecord).Error; err != nil {
			return fmt.Errorf("failed to save api key: %w", err)
		}

		// 添加 Casbin 权限策略
		if err := s.enforcer.AddAPIKeyPermissions(hash, req.Permissions); err != nil {
			// 事务会自动回滚
			return fmt.Errorf("failed to add permissions: %w", err)
		}

		// 构造响应
		var expiresAtStr *string
		if apiKeyRecord.ExpiresAt != nil {
			str := apiKeyRecord.ExpiresAt.Format(time.RFC3339)
			expiresAtStr = &str
		}

		response = &CreateAPIKeyResponse{
			ID:          apiKeyRecord.ID,
			Name:        apiKeyRecord.Name,
			Key:         key, // 返回明文，仅此一次
			Permissions: req.Permissions,
			ExpiresAt:   expiresAtStr,
			CreatedAt:   apiKeyRecord.CreatedAt.Format(time.RFC3339),
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return response, nil
}

// ListAPIKeys 列出用户的 API Keys
func (s *APIKeyService) ListAPIKeys(userID uint) ([]models.APIKey, error) {
	var keys []models.APIKey
	if err := s.db.Where("user_id = ?", userID).Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("failed to list api keys: %w", err)
	}
	return keys, nil
}

// RevokeAPIKey 吊销 API Key
func (s *APIKeyService) RevokeAPIKey(userID uint, keyID uint) error {
	// 查询 API Key
	var apiKey models.APIKey
	if err := s.db.Where("id = ? AND user_id = ?", keyID, userID).First(&apiKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAPIKeyNotFound
		}
		return fmt.Errorf("failed to find api key: %w", err)
	}

	// 使用事务保证原子性：DB 更新 + Casbin 策略删除
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// 更新为非激活状态
		if err := tx.Model(&apiKey).Update("active", false).Error; err != nil {
			return fmt.Errorf("failed to revoke api key: %w", err)
		}

		// 移除 Casbin 权限
		if err := s.enforcer.RemoveAPIKeyPermissions(apiKey.Key); err != nil {
			return fmt.Errorf("failed to remove permissions: %w", err)
		}

		return nil
	})

	return err
}

// ValidateAPIKey 验证 API Key
func (s *APIKeyService) ValidateAPIKey(key string) (*models.APIKey, error) {
	// 计算 Hash
	hash := sha256.Sum256([]byte(key))
	hashStr := hex.EncodeToString(hash[:])

	// 查询数据库
	var apiKey models.APIKey
	if err := s.db.Where("key = ? AND active = ?", hashStr, true).First(&apiKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid api key")
		}
		return nil, fmt.Errorf("failed to validate api key: %w", err)
	}

	// 检查过期时间
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, errors.New("api key has expired")
	}

	// 更新最后使用时间
	now := time.Now()
	s.db.Model(&apiKey).Update("last_used_at", now)

	return &apiKey, nil
}

// GetAPIKeyPermissions 获取 API Key 的权限列表
func (s *APIKeyService) GetAPIKeyPermissions(keyHash string) ([]string, error) {
	var apiKey models.APIKey
	if err := s.db.Where("key = ?", keyHash).First(&apiKey).Error; err != nil {
		return nil, fmt.Errorf("failed to find api key: %w", err)
	}

	var permissions []string
	if err := json.Unmarshal([]byte(apiKey.Permissions), &permissions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
	}

	return permissions, nil
}
