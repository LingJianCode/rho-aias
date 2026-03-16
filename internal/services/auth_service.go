package services

import (
	"errors"
	"time"

	"rho-aias/internal/auth/jwt"
	"rho-aias/internal/auth/password"
	"rho-aias/internal/models"

	"gorm.io/gorm"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidPassword   = errors.New("invalid password")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserInactive      = errors.New("user is inactive")
)

// AuthService 认证服务
type AuthService struct {
	db         *gorm.DB
	jwtService *jwt.JWTService
}

// NewAuthService 创建认证服务
func NewAuthService(db *gorm.DB, jwtService *jwt.JWTService) *AuthService {
	return &AuthService{
		db:         db,
		jwtService: jwtService,
	}
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	CaptchaID string `json:"captcha_id"`
	CaptchaAnswer string `json:"captcha_answer"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token    string      `json:"token"`
	User     *models.User `json:"user"`
	ExpiresAt time.Time   `json:"expires_at"`
}

// Login 用户登录
func (s *AuthService) Login(username, passwordStr string) (*LoginResponse, error) {
	// 查找用户
	var user models.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	// 检查用户状态
	if !user.Active {
		return nil, ErrUserInactive
	}

	// 验证密码
	if !password.CheckPassword(passwordStr, user.Password) {
		return nil, ErrInvalidPassword
	}

	// 生成 token
	token, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		Token:     token,
		User:      &user,
		ExpiresAt: time.Now().Add(s.jwtService.GetTokenDuration()),
	}, nil
}

// ValidateToken 验证 token
func (s *AuthService) ValidateToken(tokenString string) (*jwt.Claims, error) {
	return s.jwtService.ValidateToken(tokenString)
}

// RefreshToken 刷新 token
func (s *AuthService) RefreshToken(tokenString string) (string, error) {
	return s.jwtService.RefreshToken(tokenString)
}
