package casbin

import (
	"embed"
	"fmt"
	"strings"

	"rho-aias/internal/logger"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

//go:embed rbac_model.conf
var rbacModelFS embed.FS

// Enforcer Casbin 执行器
type Enforcer struct {
	*casbin.Enforcer
	adapter *gormadapter.Adapter
}

// NewEnforcer 创建 Casbin 执行器
func NewEnforcer(db *gorm.DB) (*Enforcer, error) {
	// 创建 GORM 适配器
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin adapter: %w", err)
	}

	// 读取模型配置
	modelData, err := rbacModelFS.ReadFile("rbac_model.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to read rbac model: %w", err)
	}

	// 创建执行器
	m, err := model.NewModelFromString(string(modelData))
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin model: %w", err)
	}
	enforcer, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}

	// 加载策略
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}

	return &Enforcer{
		Enforcer: enforcer,
		adapter:  adapter,
	}, nil
}

// InitDefaultPolicies 初始化默认策略
func (e *Enforcer) InitDefaultPolicies() error {
	// 检查是否已有策略
	policies, err := e.GetPolicy()
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	}
	if len(policies) > 0 {
		logger.Info("[Casbin] Policies already exist, skip initialization")
		return nil
	}

	logger.Info("[Casbin] Initializing default policies...")

	// 添加默认角色权限
	// role:admin 拥有所有权限（使用通配符）
	if _, err := e.AddPolicy("role:admin", "*", "*"); err != nil {
		return fmt.Errorf("failed to add admin policy: %w", err)
	}

	// role:user 拥有基础只读权限
	defaultUserPermissions := [][]string{
		{"role:user", "firewall:read", "read"},
		{"role:user", "blocklog:read", "read"},
		{"role:user", "intel:read", "read"},
		{"role:user", "geo:read", "read"},
	}

	for _, policy := range defaultUserPermissions {
		if _, err := e.AddPolicy(policy); err != nil {
			return fmt.Errorf("failed to add user policy: %w", err)
		}
	}

	// 保存策略
	if err := e.SavePolicy(); err != nil {
		return fmt.Errorf("failed to save policies: %w", err)
	}

	logger.Info("[Casbin] Default policies initialized successfully")
	return nil
}

// AssignRoleToUser 为用户分配角色
func (e *Enforcer) AssignRoleToUser(userID uint, role string) error {
	subject := fmt.Sprintf("user:%d", userID)
	roleSubject := fmt.Sprintf("role:%s", role)

	// 先移除用户的旧角色
	if _, err := e.DeleteRolesForUser(subject); err != nil {
		return fmt.Errorf("failed to delete old roles: %w", err)
	}

	// 添加新角色
	if _, err := e.AddRoleForUser(subject, roleSubject); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// GetUserRole 获取用户角色
func (e *Enforcer) GetUserRole(userID uint) string {
	subject := fmt.Sprintf("user:%d", userID)
	roles, err := e.GetRolesForUser(subject)
	if err != nil || len(roles) == 0 {
		return "user"
	}
	// 返回第一个角色（去掉 role: 前缀）
	role := roles[0]
	if len(role) > 5 && role[:5] == "role:" {
		return role[5:]
	}
	return role
}

// AddAPIKeyPermissions 为 API Key 添加权限
// 权限格式为 "resource:action"，如 "firewall:read"
func (e *Enforcer) AddAPIKeyPermissions(keyHash string, permissions []string) error {
	subject := fmt.Sprintf("apikey:%s", keyHash)

	for _, perm := range permissions {
		// 解析权限格式 "resource:action"
		parts := strings.Split(perm, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid permission format: %s, expected 'resource:action'", perm)
		}

		// 添加策略：(subject, obj, act)
		// obj 为完整权限标识（如 firewall:read），act 为操作类型（如 read）
		// 特殊处理 *:* 通配符
		obj := perm
		act := parts[1]
		if perm == "*:*" {
			obj = "*"
			act = "*"
		}

		if _, err := e.AddPolicy(subject, obj, act); err != nil {
			return fmt.Errorf("failed to add api key permission: %w", err)
		}
	}

	return nil
}

// RemoveAPIKeyPermissions 移除 API Key 的所有权限
func (e *Enforcer) RemoveAPIKeyPermissions(keyHash string) error {
	subject := fmt.Sprintf("apikey:%s", keyHash)
	if _, err := e.RemoveFilteredPolicy(0, subject); err != nil {
		return fmt.Errorf("failed to remove api key permissions: %w", err)
	}
	return nil
}
