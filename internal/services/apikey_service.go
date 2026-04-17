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
	"rho-aias/internal/logger"
	"rho-aias/internal/models"

	"gorm.io/gorm"
)

// PermissionInfo 权限信息（单一数据源，同时用于校验和前端展示）
type PermissionInfo struct {
	Value string `json:"value"` // "firewall:read"
	Label string `json:"label"` // "防火墙-读取"
}

// AllPermissions 定义全部有效权限（单一事实来源）
// 新增权限只需在此处添加一行，校验和前端展示自动同步
var allPermissions = []PermissionInfo{
	{"firewall:read",    "防火墙-读取"},
	{"firewall:write",   "防火墙-写入"},
	{"intel:read",       "威胁情报-读取"},
	{"intel:write",      "威胁情报-更新"},
	{"geo:read",         "地理位置-读取"},
	{"geo:write",        "地理位置-更新配置"},
	{"blocklog:read",    "阻断日志-读取"},
	{"blocklog:write",   "阻断日志-清除"},
	{"config:read",      "系统配置-读取"},
	{"config:write",     "系统配置-修改"},

	{"ban_record:read",  "封禁记录-读取"},
	{"ban_record:write", "封禁记录-解封"},
	{"api_key:read",     "API Key-查看"},
	{"api_key:write",    "API Key-管理"},
	{"admin:*",          "管理员全部权限"},
}

// ValidPermissions 从 allPermissions 派生的快速查找集合
// 用于 CreateAPIKey 中 O(1) 校验前端传入的 permissions 字段
var ValidPermissions = func() map[string]bool {
	m := make(map[string]bool, len(allPermissions))
	for _, p := range allPermissions {
		m[p.Value] = true
	}
	return m
}()

// GetValidPermissions 返回有效权限列表（供前端渲染权限选择器）
func (s *APIKeyService) GetValidPermissions() []PermissionInfo {
	return allPermissions
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

	// 更新最后使用时间（原子操作：基于主键更新并检查影响行数）
	now := time.Now()
	result := s.db.Model(&apiKey).Update("last_used_at", now)
	if result.Error != nil {
		logger.Warnf("[APIKey] Failed to update last_used_at for key %s: %v", apiKey.KeyPrefix, result.Error)
	} else if result.RowsAffected == 0 {
		logger.Warnf("[APIKey] last_updated update affected 0 rows (key may have been deleted): %s", apiKey.KeyPrefix)
	}

	// 清除敏感字段后再返回，防止哈希值泄露
	apiKey.Key = ""
	return &apiKey, nil
}
