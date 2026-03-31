package handles

import (
	"net/http"

	"rho-aias/internal/auth/captcha"
	"rho-aias/internal/response"
	"rho-aias/internal/services"

	"github.com/gin-gonic/gin"
)

// AuthHandle 认证处理器
type AuthHandle struct {
	authService    *services.AuthService
	userService    *services.UserService
	captchaService *captcha.CaptchaService
}

// NewAuthHandle 创建认证处理器
func NewAuthHandle(
	authService *services.AuthService,
	userService *services.UserService,
	captchaService *captcha.CaptchaService,
) *AuthHandle {
	return &AuthHandle{
		authService:    authService,
		userService:    userService,
		captchaService: captchaService,
	}
}

// GetCaptcha 获取验证码
// @Summary 获取验证码
// @Description 生成图形验证码用于登录
// @Tags 认证
// @Produce json
// @Success 200 {object} map[string]string
// @Router /api/auth/captcha [get]
func (h *AuthHandle) GetCaptcha(c *gin.Context) {
	id, img, err := h.captchaService.Generate()
	if err != nil {
		response.InternalError(c, "failed to generate captcha")
		return
	}

	response.OK(c, gin.H{
		"captcha_id":    id,
		"captcha_image": img,
	})
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username     string `json:"username" binding:"required"`
	Password     string `json:"password" binding:"required"`
	CaptchaID    string `json:"captcha_id" binding:"required"`
	CaptchaCode  string `json:"captcha_code" binding:"required"`
}

// Login 登录
// @Summary 用户登录
// @Description 使用用户名密码登录
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body LoginRequest true "登录请求"
// @Success 200 {object} services.LoginResponse
// @Failure 401 {object} map[string]string
// @Router /api/auth/login [post]
func (h *AuthHandle) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request")
		return
	}

	// 验证验证码
	if !h.captchaService.Verify(req.CaptchaID, req.CaptchaCode) {
		response.Fail(c, http.StatusBadRequest, response.CodeInvalidCaptcha, "invalid captcha")
		return
	}

	// 登录
	resp, err := h.authService.Login(req.Username, req.Password)
	if err != nil {
		switch err {
		case services.ErrUserNotFound, services.ErrInvalidPassword:
			response.Fail(c, http.StatusUnauthorized, response.CodeInvalidPassword, "invalid username or password")
		case services.ErrUserInactive:
			response.Fail(c, http.StatusForbidden, response.CodeUserInactive, "user is inactive")
		default:
			response.InternalError(c, "login failed")
		}
		return
	}

	response.OK(c, resp)
}

// RefreshTokenRequest 刷新 token 请求
type RefreshTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

// RefreshToken 刷新 token
// @Summary 刷新 token
// @Description 刷新过期的 token
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "刷新请求"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/auth/refresh [post]
func (h *AuthHandle) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request")
		return
	}

	newToken, err := h.authService.RefreshToken(req.Token)
	if err != nil {
		response.Unauthorized(c, "failed to refresh token")
		return
	}

	response.OK(c, gin.H{
		"token": newToken,
	})
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

// ChangePassword 修改密码
// @Summary 修改密码
// @Description 修改当前用户密码
// @Tags 认证
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ChangePasswordRequest true "修改密码请求"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/auth/password [put]
func (h *AuthHandle) ChangePassword(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		response.Unauthorized(c, "unauthorized")
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request")
		return
	}

	err := h.userService.ChangePassword(userID.(uint), req.OldPassword, req.NewPassword)
	if err != nil {
		switch err {
		case services.ErrPasswordIncorrect:
			response.BadRequest(c, "current password is incorrect")
		default:
			response.InternalError(c, "failed to change password")
		}
		return
	}

	response.OKMsg(c, "password changed successfully")
}

// GetCurrentUser 获取当前用户信息
// @Summary 获取当前用户信息
// @Description 获取当前登录用户的详细信息
// @Tags 认证
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.User
// @Failure 401 {object} map[string]string
// @Router /api/auth/me [get]
func (h *AuthHandle) GetCurrentUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		response.Unauthorized(c, "unauthorized")
		return
	}

	user, err := h.userService.GetUserByID(userID.(uint))
	if err != nil {
		response.InternalError(c, "failed to get user info")
		return
	}

	response.OK(c, user)
}

// Logout 登出（客户端删除 token 即可）
// @Summary 登出
// @Description 用户登出（客户端需删除 token）
// @Tags 认证
// @Success 200 {object} map[string]string
// @Router /api/auth/logout [post]
func (h *AuthHandle) Logout(c *gin.Context) {
	response.OKMsg(c, "logged out successfully")
}
