package services

import (
	"errors"

	"rho-aias/internal/auth/password"
	"rho-aias/internal/models"

	"gorm.io/gorm"
)

var (
	ErrPasswordIncorrect = errors.New("current password is incorrect")
	ErrPasswordTooWeak   = errors.New("password is too weak")
)

// UserService 用户服务
type UserService struct {
	db *gorm.DB
}

// NewUserService 创建用户服务
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

// CreateUser 创建用户
func (s *UserService) CreateUser(username, passwordStr, nickname, email, role string) (*models.User, error) {
	// 检查用户名是否存在
	var count int64
	s.db.Model(&models.User{}).Where("username = ?", username).Count(&count)
	if count > 0 {
		return nil, ErrUserAlreadyExists
	}

	// 加密密码
	hashedPassword, err := password.HashPassword(passwordStr)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Username: username,
		Password: hashedPassword,
		Nickname: nickname,
		Email:    email,
		Role:     role,
		Active:   true,
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

// GetUserByID 根据 ID 获取用户
func (s *UserService) GetUserByID(id uint) (*models.User, error) {
	var user models.User
	if err := s.db.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername 根据用户名获取用户
func (s *UserService) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// ListUsers 列出所有用户
func (s *UserService) ListUsers() ([]models.User, error) {
	var users []models.User
	if err := s.db.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

// UpdateUser 更新用户信息
func (s *UserService) UpdateUser(id uint, updates map[string]interface{}) error {
	return s.db.Model(&models.User{}).Where("id = ?", id).Updates(updates).Error
}

// ChangePassword 修改密码
func (s *UserService) ChangePassword(userID uint, oldPassword, newPassword string) error {
	// 获取用户
	user, err := s.GetUserByID(userID)
	if err != nil {
		return err
	}

	// 验证旧密码
	if !password.CheckPassword(oldPassword, user.Password) {
		return ErrPasswordIncorrect
	}

	// 加密新密码
	hashedPassword, err := password.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// 更新密码
	return s.db.Model(user).Update("password", hashedPassword).Error
}

// DeleteUser 删除用户（软删除）
func (s *UserService) DeleteUser(id uint) error {
	return s.db.Delete(&models.User{}, id).Error
}

// SetUserActive 设置用户状态
func (s *UserService) SetUserActive(id uint, active bool) error {
	return s.db.Model(&models.User{}).Where("id = ?", id).Update("active", active).Error
}
